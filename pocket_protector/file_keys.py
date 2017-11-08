'''
Functions and classes for dealing with a checked-in file,
protected.yaml, which stores secret data securely.

There are two public classes: KeyFile, and Creds.
'''
import base64
import collections
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


_FILE_SCHEMA = schema.Schema(
{
    "audit-log": [str],
    "key-custodians": {
        schema.Optional(str): {
            "public-key": str,
            "encrypted-private-key": str,
        },
    },
    schema.Optional(schema.Regex("^(?!meta).*$")): {
    # allow string names for security domains,
    # but meta is reserved
        "meta": {
            "owners": {str: str},
            "public-key": str,
        },
        schema.Optional(schema.Regex("secret-.*")): str,
    },
})


class KeyDomainError(ValueError): pass


Creds = attr.make_class('KeyCustodianCreds', ['name', 'passphrase'])
# credentials that can be entered by a user; associated with
# NOTE: this is a public class since it must be passed in


def _kdf(creds):
    return nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        creds.passphrase, hashlib.sha512(creds.name).digest()[:16],
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE)


@attr.s(frozen=True)
class _KeyCustodian(object):
    '''
    represents a key-custodian, who may be granted ownership
    (aka the ability to decrypt secrets) in one or more domains
    '''
    name = attr.ib()
    _public_key = attr.ib()
    _enc_custodian_private_key = attr.ib()

    def encrypt_for(self, bytes):
        'encrypt the passed bytes so that this key-custodian can decrypt'
        return nacl.public.SealedBox(self._public_key).encrypt(bytes)

    def decrypt_as(self, creds, bytes):
        'decrypt the passed bytes that were encrypted for this key-custodian'
        assert creds.name == self.name
        derived_key = _kdf(creds)
        return nacl.public.SealedBox(nacl.public.PrivateKey(
            nacl.secret.SecretBox(derived_key).decrypt(
                self._enc_custodian_private_key))).decrypt(bytes)

    def set_passphrase(self, creds, new_passphrase):
        'return a copy with an updated passphrase'
        assert creds.name == self.name
        derived_key = _kdf(creds)
        private_key_bytes = nacl.secret.SecretBox(
            derived_key).decrypt(self._enc_custodian_private_key)
        new_derived_key = _kdf(Creds(self.name, new_passphrase))
        new_enc_priv_key_bytes = nacl.secret.SecretBox(
            new_derived_key).encrypt(private_key_bytes)
        return attr.evolve(
            self, enc_custodian_private_key=new_enc_priv_key_bytes)

    @classmethod
    def from_creds(cls, creds):
        'create a new user based on new credentials'
        private_key = nacl.public.PrivateKey.generate()
        derived_key = _kdf(creds)
        encrypted_private_key = nacl.secret.SecretBox(
            derived_key).encrypt(private_key.encode())
        return cls(
            name=creds.name, public_key=private_key.public_key,
            enc_custodian_private_key=encrypted_private_key)

    @classmethod
    def from_data(cls, name, data):
        return cls(
            name=name,
            public_key=nacl.public.PublicKey(
                base64.b64decode(data['public-key'])),
            enc_custodian_private_key=base64.b64decode(
                data['encrypted-private-key']),
        )

    def as_data(self):
        return {
            'public-key':
                base64.b64encode(self._public_key.encode()),
            'encrypted-private-key':
                base64.b64encode(self._enc_custodian_private_key),
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
        return cls(name, base64.b64decode(encrypted_private_key_bytes))

    def as_data(self):
        return base64.b64encode(self._enc_domain_private_key)


class PPError(Exception): pass
class PPKeyError(PPError, KeyError): pass


def _err_map_attrib(item_name):
    class MissingErrDict(dict):
        def __missing__(self, key):
            raise PPKeyError("no {0} of name {1} (known {0}s are {2})".format(
                item_name, key, ", ".join(self)))
    return attr.ib(default=attr.Factory(dict), convert=MissingErrDict)


@attr.s(frozen=True)
class _EncryptedKeyDomain(object):
    'Represents a key domain with all values encrypted.'
    _name = attr.ib()
    _pub_key = attr.ib()
    _secrets = attr.ib()
    _owners = _err_map_attrib('key custodian')

    def _decrypt_private_key(self, key_custodian, creds):
        return nacl.public.PrivateKey(
            self._owners[creds.name].decrypt_private_key_bytes(
                creds, key_custodian))

    def get_decrypted(self, key_custodian, creds):
        if creds.name not in self._owners:
            raise ValueError('{} is not an owner of {}'.format(
                creds.name, self._name))
        box = nacl.public.SealedBox(self._decrypt_private_key(
            key_custodian, creds))
        secrets = {}
        for name, val in self._secrets.items():
            secrets[name] = box.decrypt(val)
        return _KeyDomain(secrets)

    def set_secret(self, name, value):
        'return a copy of the EncryptedKeyDomain with the new secret name/value'
        secrets = self._secrets
        box = nacl.public.SealedBox(self._pub_key)
        secrets[name] = box.encrypt(value)
        return attr.evolve(self, secrets=secrets)

    def add_owner(self, cur_creds, cur_key_custodian, new_key_custodian):
        'add a new owner based on a current owners credentials'
        domain_private_key = self._decrypt_private_key(
            cur_key_custodian, cur_creds)
        owners = dict(self._owners)
        owners[new_key_custodian.name] = _Owner.from_custodian_and_pkey(
            new_key_custodian, domain_private_key)
        return attr.evolve(self, owners=owners)

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
                base64.b64decode(data['meta']['public-key'])),
            owners={
                name: _Owner.from_data(name, owner_data)
                for name, owner_data in data['meta']['owners'].items()},
            secrets={
                name.split('secret-', 1)[1]: base64.b64decode(val)
                for name, val in data.items()
                if name.startswith('secret-')})

    def as_data(self):
        'convert instance to nested dict/list/str'
        data = { "secret-" + name: base64.b64encode(val)
                 for name, val in self._secrets.items() }
        # ensure keys go in sorted order
        data = collections.OrderedDict(sorted(data.items()))
        data['meta'] = collections.OrderedDict([
            ("public-key", base64.b64encode(self._pub_key.encode())),
            ("owners", collections.OrderedDict(
                sorted([(name, owner.as_data()) for name, owner in self._owners.items()]))),
        ])
        return data


@attr.s(frozen=True)
class _KeyDomain(object):
    'Represents a decrypted key domain which secrets can be read from'
    _secrets = _err_map_attrib('secret')

    def __getitem__(self, name):
        return self._secrets[name]


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
    _path = attr.ib()
    _domains = _err_map_attrib('domain')
    _key_custodians = _err_map_attrib('key custodian')
    _log = attr.ib(default=attr.Factory(list))
    _yaml = ruamel.yaml.YAML()  # class var

    @classmethod
    def from_file(cls, path):
        'create a new KeyFile from path'
        with open(path, 'rb') as file:
            contents = file.read()
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

    def write(self):  # TODO: need way to get contents.
        'write contents to file'
        contents = self.get_contents()
        with open(self._path, 'wb') as file:  # TODO: AtomicSaver
            file.write(contents)
        return

    def add_domain(self, domain_name, key_custodian_name):
        '''
        return a copy with a new domain, empty but with one initial key custodian
        owner who can add other owners
        '''
        if domain_name in self._domains:
            raise ValueError('tried to add domain that already exists: {}'.format(domain_name))
        key_custodian = self._key_custodians[key_custodian_name]
        domains = dict(self._domains)
        domains[domain_name] = _EncryptedKeyDomain.from_owner(
            domain_name, key_custodian)
        return attr.evolve(
            self, domains=domains,
            log=self._log + ['created domain {} with owner {}'.format(
                domain_name, key_custodian_name)])

    def set_secret(self, domain_name, name, value):
        'return a copy of the KeyFile with the given secret name and value added to a domain'
        domains = dict(self._domains)
        domains[domain_name] = self._domains[domain_name].set_secret(name, value)
        return attr.evolve(
            self, domains=domains,
            log=self._log + ['created secret {} in {}'.format(name, domain_name)])

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
            log=self._log + ['{} added owner {} to {}'.format(
                creds.name, key_custodian_name, domain_name)])

    def add_key_custodian(self, creds):
        key_custodians = dict(self._key_custodians)
        key_custodians[creds.name] = _KeyCustodian.from_creds(creds)
        return attr.evolve(
            self, key_custodians=key_custodians,
            log=self._log + ['created key custodian {}'.format(creds.name)])

    def decrypt_domain(self, domain_name, creds):
        return self._domains[domain_name].get_decrypted(
            self._key_custodians[creds.name], creds)

    def set_key_custodian_passphrase(self, creds, new_passphrase):
        key_custodian = self._key_custodians[creds.name]
        key_custodians = dict(self._key_custodians)
        key_custodians[creds.name] = key_custodian.set_passphrase(
            creds, new_passphrase)
        return attr.evolve(self, key_custodians=key_custodians)

    def check_creds(self, creds):
        try:
            key_custodian = self._key_custodians[creds.name]
        except KeyError:
            return False
        try:
            key_custodian.decrypt_as(creds, key_custodian.encrypt_for('\0'))
        except Exception:  # TODO: what crypto error?
            return False
        return True

    def rotate_key_custodian_key(self, creds):
        '''
        rotate the key custodian keypair
        NIST recommends keys be rotated and not kept in use for more than ~1-3 years
        see http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
        Recommendation for Key Management, Part 1: General
        section 5.3.6 Cryptoperiod Recommendations for Specific Key Types
        '''
        raise NotImplemented

    def rotate_domain_key(self, domain_name, creds):
        '''
        rotate the keypair used to secure a domain
        '''
        raise NotImplemented
