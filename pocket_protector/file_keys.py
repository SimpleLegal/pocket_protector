'''
Functions and classes for dealing with a checked-in file,
protected.yaml, which stores secret data securely.

There are two public classes: KeyFile, and Creds.
'''
import os
import re
import base64
import collections
import datetime
import hashlib
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import attr
import nacl.utils
import nacl.public
import nacl.secret
import nacl.pwhash
import schema
import ruamel.yaml
from boltons.dictutils import OMD
from boltons.fileutils import atomic_save

try:
    unicode = unicode
except NameError:
    unicode = str  # py3


_VALID_NAME_RE = re.compile(r"^[A-z][-_A-z0-9]*\Z")


class PPError(Exception):
    pass


class PPKeyError(PPError, KeyError):
    pass


# _coerce to handle ruamel type switcheroo
def _coerce(type_, sub_schema):
    return schema.And(schema.Use(type_), sub_schema)


def _as_d(sub_schema): return _coerce(dict, sub_schema)
def _as_l(sub_schema): return _coerce(list, sub_schema)


_FILE_SCHEMA = schema.Schema(_as_d(
{
    "audit-log": _as_l([str]),
    "key-custodians": _as_d({
        schema.Optional(str): _as_d({
            "pwdkm": str,
        }),
    }),
    schema.Optional(schema.Regex("^(?!meta).*$")): _as_d({
        # allow string names for security domains,
        # but meta is reserved
        "meta": _as_d({
            "owners": _as_d({str: str}),
            "public-key": str,
        }),
        schema.Optional(schema.Regex("secret-.*")): str,
    }),
}))


OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE
MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE

# NOTE: this is a public class since it must be passed in
@attr.s(frozen=True)
class Creds(object):
    "Stores credentials used to open a KeyFile"
    name = attr.ib(validator=attr.validators.instance_of(unicode))
    passphrase = attr.ib(validator=attr.validators.instance_of(unicode))
    name_source = attr.ib(default=None)
    passphrase_source = attr.ib(default=None)


def _kdf(creds, salt):
    name = creds.name.encode('utf8')
    passphrase = creds.passphrase.encode('utf8')

    valet_key = hashlib.sha512(passphrase + salt + name).digest()
    # valet key can be used to share credentials
    # without exposing password
    return nacl.pwhash.argon2id.kdf(
        nacl.public.PrivateKey.SIZE,
        valet_key, hashlib.sha512(salt + name).digest()[:16],
        opslimit=OPSLIMIT,
        memlimit=MEMLIMIT)


def _decode(b64):
    '''
    assert everything is version 0
    later on for e.g. algorithm flexibility
    version 1, 2, 3 could be added with object
    specific encoder / decoder
    (this would be a lot of code work, but the files would
    be forwards compatible, and backwards can at least
    detect the problem and notify the user cleanly)
    '''
    raw = base64.b64decode(b64)
    if raw[:1] == b'\0':
        return raw[1:]
    raise PPError('version %s object not supported' % ord(raw[:1]))


def _encode(raw):
    'add version 0 byte to everything'
    return base64.b64encode(b'\0' + raw).decode('utf8')


@attr.s(frozen=True)
class _KeyCustodian(object):
    '''
    represents a key-custodian, who may be granted ownership
    (aka the ability to decrypt secrets) in one or more domains
    '''
    name = attr.ib()
    _public_key = attr.ib()
    _salt = attr.ib()

    def encrypt_for(self, bytes):
        'encrypt the passed bytes so that this key-custodian can decrypt'
        return nacl.public.SealedBox(self._public_key).encrypt(bytes)

    def decrypt_as(self, creds, bytes):
        'decrypt the passed bytes that were encrypted for this key-custodian'
        assert creds.name == self.name
        return nacl.public.SealedBox(
            nacl.public.PrivateKey(_kdf(creds, self._salt))).decrypt(bytes)

    @classmethod
    def from_creds(cls, creds):
        'create a new user based on new credentials'
        salt = os.urandom(8)
        private_key = nacl.public.PrivateKey(_kdf(creds, salt))
        return cls(
            name=creds.name, public_key=private_key.public_key, salt=salt)

    @classmethod
    def from_data(cls, name, data):
        # password derived key material
        pwdkm = _decode(data['pwdkm'])
        salt, public_key = pwdkm[:8], pwdkm[8:8 + nacl.public.PublicKey.SIZE]
        return cls(
            name=name, public_key=nacl.public.PublicKey(public_key), salt=salt)

    def as_data(self):
        return {
            'pwdkm': _encode(self._salt + self._public_key.encode()),
        }


@attr.s(frozen=True)
class _Owner(object):
    'represents an ownership relationship between a key-custodian and a key-domain'
    _name = attr.ib()
    _enc_domain_private_key = attr.ib()

    @classmethod
    def from_custodian_and_pkey(cls, key_custodian, pkey):
        '''
        create an ownership relationship based on a key_custodian
        and decrypted private key
        '''
        return cls(key_custodian.name, key_custodian.encrypt_for(pkey.encode()))

    def decrypt_private_key_bytes(self, creds, key_custodian):
        'decrypt the private key based on the passphrase'
        return key_custodian.decrypt_as(creds, self._enc_domain_private_key)

    @classmethod
    def from_data(cls, name, encrypted_private_key_bytes):
        return cls(name, _decode(encrypted_private_key_bytes))

    def as_data(self):
        return _encode(self._enc_domain_private_key)


def _err_map_attrib(item_name):
    'utility for giving good error messages'
    class MissingErrDict(dict):
        def __missing__(self, key):
            raise PPKeyError("no {0} of name {1} (known {0}s are {2})".format(
                item_name, key, ", ".join(self)))
    return attr.ib(default=attr.Factory(dict), converter=MissingErrDict)


def _deleted(mapping, key):
    '''
    like sort() vs sorted(), return a dict copy of mapping
    with key del'd out
    '''
    ret = dict(mapping)
    del ret[key]
    return ret


def _setitem(mapping, key, val):
    '''
    returns a dict-copy of mapping with key set to val
    '''
    ret = dict(mapping)
    ret[key] = val
    return ret


@attr.s(frozen=True)
class _EncryptedKeyDomain(object):
    'Represents a key domain with all values encrypted.'
    _name = attr.ib()
    _pub_key = attr.ib()
    _secrets = _err_map_attrib('secret')
    _owners = _err_map_attrib('owner')

    def _decrypt_private_key(self, key_custodian, creds):
        return nacl.public.PrivateKey(
            self._owners[creds.name].decrypt_private_key_bytes(
                creds, key_custodian))

    def get_decrypted(self, key_custodian, creds):
        if creds.name not in self._owners:
            raise PPError('{} is not an owner of {}'.format(
                creds.name, self._name))
        box = nacl.public.SealedBox(self._decrypt_private_key(
            key_custodian, creds))
        secrets = {}
        for name, val in self._secrets.items():
            secrets[name] = box.decrypt(val).decode('utf8')
        return _KeyDomain(secrets)

    def set_secret(self, name, value):
        'return a copy of the EncryptedKeyDomain with the new secret name/value'
        name_match = _VALID_NAME_RE.match(name)
        if not name_match:
            raise ValueError('valid secret names must begin with a letter, and'
                             ' consist only of ASCII letters, digits, and'
                             ' underscores, not: %r' % name)

        secrets = dict(self._secrets)
        box = nacl.public.SealedBox(self._pub_key)
        secrets[name] = box.encrypt(value.encode('utf8'))
        return attr.evolve(self, secrets=secrets)

    def add_secret(self, name, value):
        'like set_secret, but errors if secret exists'
        if name in self._secrets:
            raise PPError('secret {} already exists in {}'.format(
                name, self._name))
        return self.set_secret(name, value)

    def update_secret(self, name, value):
        'like set_secret, but errors if secret doesnt exist'
        chk = self._secrets[name]  # for error msg
        return self.set_secret(name, value)

    def rm_secret(self, name):
        return attr.evolve(self, secrets=_deleted(self._secrets, name))

    def add_owner(self, cur_creds, cur_key_custodian, new_key_custodian):
        'add a new owner based on a current owners credentials'
        domain_private_key = self._decrypt_private_key(
            cur_key_custodian, cur_creds)
        owners = dict(self._owners)
        owners[new_key_custodian.name] = _Owner.from_custodian_and_pkey(
            new_key_custodian, domain_private_key)
        return attr.evolve(self, owners=owners)

    def rm_owner(self, key_custodian_name):
        'remove owner, checking that domain has at least one user'
        if key_custodian_name not in self._owners:
            raise PPError("{} not an owner of {} (owners are {})".format(
                key_custodian_name, self._name, ", ".join(self._owners)))
        if len(self._owners) == 1:
            raise PPError(
                "cannot delete last owner {} from {} "
                "(secrets would be irretrievable)".format(key_custodian_name, self._name))
        return attr.evolve(self, owners=_deleted(self._owners, key_custodian_name))

    def get_owner_names(self):
        return list(self._owners)

    @classmethod
    def from_owner(cls, name, key_custodian):
        'create a new (empty) EncryptedKeyDomain with an initial owner'
        domain_private_key = nacl.public.PrivateKey.generate()
        return cls(
            name=name,
            pub_key=domain_private_key.public_key,
            secrets={},
            owners={
                key_custodian.name:
                    _Owner.from_custodian_and_pkey(
                        key_custodian, domain_private_key)})

    @classmethod
    def from_data(cls, name, data):
        'convert nested dict/list/str to instance'
        return cls(
            name=name,
            pub_key=nacl.public.PublicKey(
                _decode(data['meta']['public-key'])),
            owners={
                name: _Owner.from_data(name, owner_data)
                for name, owner_data in data['meta']['owners'].items()},
            secrets={
                name.split('secret-', 1)[1]: _decode(val)
                for name, val in data.items()
                if name.startswith('secret-')})

    def as_data(self):
        'convert instance to nested dict/list/str'
        data = { "secret-" + name: _encode(val)
                 for name, val in self._secrets.items() }
        # ensure keys go in sorted order
        data = collections.OrderedDict(sorted(data.items()))
        data['meta'] = collections.OrderedDict([
            ("public-key", _encode(self._pub_key.encode())),
            ("owners", collections.OrderedDict(
                sorted([(name, owner.as_data()) for name, owner in self._owners.items()]))),
        ])
        return data


class _KeyDomain(dict):
    'Represents a decrypted key domain which secrets can be read from'
    def __missing__(self, key):
        raise PPKeyError("no secret {} (known secrets are {})".format(
            key, ", ".join(self)))


def _represent_ordereddict(dumper, data):
    value = []
    for item_key, item_value in data.items():
        node_key = dumper.represent_data(item_key)
        node_value = dumper.represent_data(item_value)
        value.append((node_key, node_value))
    return ruamel.yaml.nodes.MappingNode(u'tag:yaml.org,2002:map', value)


ruamel.yaml.representer.RoundTripRepresenter.add_representer(
    collections.OrderedDict, _represent_ordereddict)


@attr.s(frozen=True)
class KeyFile(object):
    '''
    Represents a key-file (containing many domains)
    Can be read from and written to disk
    '''
    path = attr.ib()
    _domains = _err_map_attrib('domain')
    _key_custodians = _err_map_attrib('key custodian')
    _log = attr.ib(default=attr.Factory(list))
    _yaml = ruamel.yaml.YAML()  # class var
    _yaml.width = 100

    @classmethod
    def from_file(cls, path):
        'create a new KeyFile from path'
        with open(path, 'rb') as file:
            contents = file.read().decode('utf8')
        return cls.from_contents_and_path(contents, path)

    @classmethod
    def from_contents_and_path(cls, bytes, path):
        'create a new KeyFile from file contents'
        contents = cls._yaml.load(bytes)
        _FILE_SCHEMA.validate(contents)
        log = contents.pop('audit-log')
        key_custodians = {
            name: _KeyCustodian.from_data(name, val)
            for name, val in contents.pop('key-custodians').items()}
        encrypted_domains = {
            name: _EncryptedKeyDomain.from_data(name, data)
            for name, data in contents.items() }
        return cls(
            path=path, domains=encrypted_domains,
            key_custodians=key_custodians, log=log)

    def get_domain_names(self):
        return sorted(self._domains.keys())

    def get_domain_secret_names(self, domain_name):
        domain = self._domains[domain_name]
        return sorted(domain._secrets.keys())

    def get_all_secret_names(self):
        "return a map of secret names to names of domains that contain that secret"
        res = OMD()
        for domain_name, domain in self._domains.items():
            secrets_dict = domain._secrets
            for secret_name in secrets_dict:
                res.add(secret_name, domain_name)
        return dict(res)

    def get_contents(self):
        data = collections.OrderedDict(sorted([
            (domain_name, domain.as_data())
            for domain_name, domain in self._domains.items()]))
        data['key-custodians'] = collections.OrderedDict(sorted([
            (name, kc.as_data())
            for name, kc in self._key_custodians.items()]))
        data['audit-log'] = self._log
        stream = StringIO()
        self._yaml.dump(data, stream)
        text = stream.getvalue()
        return text

    def _new_log(self, entry, *a, **kw):
        cur_time_str = datetime.datetime.utcnow().isoformat().split('.')[0] + 'Z'
        new_entry = cur_time_str + ' -- ' + (entry.format(*a, **kw))
        return self._log + [new_entry]

    def get_audit_log(self):
        return list(self._log)

    def write(self):  # TODO: need way to get contents.
        'write contents to file'
        contents = self.get_contents()
        with atomic_save(self.path) as file:
            file.write(contents.encode('utf8'))
        return

    def add_domain(self, domain_name, key_custodian_name):
        '''
        return a copy with a new domain, empty but with one initial key custodian
        owner who can add other owners
        '''
        if domain_name in self._domains:
            raise PPError('tried to add domain that already exists: {}'.format(domain_name))
        key_custodian = self._key_custodians[key_custodian_name]
        domains = dict(self._domains)
        domains[domain_name] = _EncryptedKeyDomain.from_owner(
            domain_name, key_custodian)
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('created domain {} with owner {}',
                              domain_name, key_custodian_name))

    def rm_domain(self, domain_name):
        '''
        return a copy with domain domain_name removed
        '''
        return attr.evolve(
            self, domains=_deleted(self._domains, domain_name),
            log=self._new_log('deleted domain {}', domain_name))

    def set_secret(self, domain_name, name, value):
        'return a copy of the KeyFile with the given secret name and value added to a domain'
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].set_secret(name, value)
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('set secret {} in {}', name, domain_name))

    def add_secret(self, domain_name, name, value):
        'add a secret that doesnt exist yet'
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].add_secret(name, value)
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('added secret {} in {}', name, domain_name))

    def update_secret(self, domain_name, name, value):
        'update the value of a secret that already exists'
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].update_secret(name, value)
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('updated secret {} in {}', name, domain_name))

    def rm_secret(self, domain_name, name):
        'return a copy with secret removed from domain'
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].rm_secret(name)
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('removed secret {} from {}', name, domain_name))

    def add_owner(self, domain_name, key_custodian_name, creds):
        '''
        Register a new key custodian owner of domain_name based on the
        credentials of an existing owner
        '''
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].add_owner(
            cur_creds=creds, cur_key_custodian=self._key_custodians[creds.name],
            new_key_custodian=self._key_custodians[key_custodian_name])
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('{} added owner {} to {}',
                creds.name, key_custodian_name, domain_name))

    def rm_owner(self, domain_name, key_custodian_name):
        '''
        Remove an owner from domain.
        (NOTE: due to file history, the removed owner
        will still be able to get to values until you rotate
        the domain keypair, and secret values)
        '''
        return attr.evolve(
            self, domains=_setitem(
                self._domains, domain_name,
                self._domains[domain_name].rm_owner(key_custodian_name)),
            log=self._new_log('removed owner {} from {}',
                key_custodian_name, domain_name))

    def add_key_custodian(self, creds):
        key_custodians = dict(self._key_custodians)
        if creds.name in key_custodians:
            raise PPError(
                'tried to add key custodian that already exists: {}'.format(creds.name))
        key_custodians[creds.name] = _KeyCustodian.from_creds(creds)
        return attr.evolve(
            self, key_custodians=key_custodians,
            log=self._new_log('created key custodian {}', creds.name))

    def rm_key_custodian(self, key_custodian_name):
        'remove key custodian and all domain ownerships'
        key_custodians = dict(self._key_custodians)
        domains = dict(self._domains)
        owned = []
        for name, domain in self._domains.items():
            if key_custodian_name in domain.get_owner_names():
                domains[name] = domain.rm_owner(key_custodian_name)
                owned.append(name)
        del key_custodians[key_custodian_name]
        return attr.evolve(
            self, key_custodians=key_custodians, domains=domains,
            log=self._new_log('removed key custodian {} (was owner of {})',
                key_custodian_name, ", ".join(owned)))

    def decrypt_domain(self, domain_name, creds):
        return self._domains[domain_name].get_decrypted(
            self._key_custodians[creds.name], creds)

    def set_key_custodian_passphrase(self, creds, new_passphrase):
        new_kc = _KeyCustodian.from_creds(Creds(creds.name, new_passphrase))
        cur_kc = self._key_custodians[creds.name]
        key_custodians = dict(self._key_custodians)
        key_custodians[creds.name] = new_kc
        domains = dict(self._domains)
        updated = []
        for name, domain in domains.items():
            if creds.name in domain.get_owner_names():
                domains[name] = self._domains[name].add_owner(
                    cur_creds=creds, cur_key_custodian=cur_kc,
                    new_key_custodian=new_kc)
                updated.append(name)
        return attr.evolve(
            self, key_custodians=key_custodians, domains=domains,
            log=self._new_log(
                'updated key custodian passphrase for {} (updated domains -> {})',
                    creds.name, ", ".join(updated)))

    def check_creds(self, creds):
        try:
            key_custodian = self._key_custodians[creds.name]
        except KeyError:
            return False
        try:
            key_custodian.decrypt_as(creds, key_custodian.encrypt_for(b'\0'))
        except Exception:  # TODO: what crypto error?
            return False
        return True

    def rotate_domain_key(self, domain_name, creds):
        '''
        rotate the keypair used to secure a domain
        NIST recommends keys be rotated and not kept in use for more than ~1-3 years
        see http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
        Recommendation for Key Management, Part 1: General
        section 5.3.6 Cryptoperiod Recommendations for Specific Key Types
        '''
        cur_domain = self._domains[domain_name]
        key_custodian = self._key_custodians[creds.name]
        cur_secrets = cur_domain.get_decrypted(key_custodian, creds)
        new_domain = _EncryptedKeyDomain.from_owner(domain_name, key_custodian)
        for name, val in cur_secrets.items():
            new_domain = new_domain.set_secret(name, val)
        for owner_name in cur_domain.get_owner_names():
            new_domain = new_domain.add_owner(
                cur_creds=creds, cur_key_custodian=key_custodian,
                new_key_custodian=self._key_custodians[owner_name])
        domains = dict(self._domains)
        domains[domain_name] = new_domain
        return attr.evolve(
            self, domains=domains,
            log=self._new_log('rotated key for domain {}', domain_name))

    def truncate_audit_log(self, max_keep):
        max_keep = int(max_keep)
        if len(self._log) < max_keep:
            return self
        msg = 'truncated %s audit log entries' % (len(self._log) - max_keep)
        new_log = [msg] + self._log[-max_keep:]
        return attr.evolve(self, log=new_log)
