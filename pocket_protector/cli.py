# -*- coding: utf-8 -*-
"""
pocket_protector

People-centric secret management system, built to work with modern distributed version control systems.
"""
# Note that the doc above is part of "pprotect -h" output, add to it wisely.

import os
import sys
import json
import difflib

from face import Command, Flag, face_middleware, CommandLineError, UsageError, echo, prompt

from ._version import __version__
from .file_keys import KeyFile, Creds, PPError

_ANSI_FORE_RED = '\x1b[31m'
_ANSI_FORE_GREEN = '\x1b[32m'
_ANSI_RESET_ALL = '\x1b[0m'

# TODO: custodian-signed values. allow custodians to sign values
# added/set by others, then produced reports on which secrets have been
# updated/changed but not signed yet. enables a review/audit mechanism.

try:
    unicode
except NameError:
    # py3
    unicode = str


def _get_text(inp):
    if not isinstance(inp, unicode):
        return inp.decode('utf8')
    return inp


def _create_protected(path):
    if os.path.exists(path):
        raise UsageError('Protected file already exists: %s' % path, 2)
    open(path, 'wb').close()
    kf = KeyFile(path=path)
    # TODO: add audit log entry for creation date
    # TODO: add audit log dates in general
    kf.write()
    return kf


def _ensure_protected(path):
    if not os.path.exists(path):
        raise UsageError('Protected file not found: %s' % path, 2)
    kf = KeyFile.from_file(path)
    return kf


def _get_colorized_lines(lines):
    ret = []
    colors = {'-': _ANSI_FORE_RED, '+': _ANSI_FORE_GREEN}
    for line in lines:
        if line[0] in colors:
            line = colors[line[0]] + line + _ANSI_RESET_ALL
        ret.append(line)
    return ret


def _get_new_creds(confirm=True):
    user_id = prompt('User email: ')
    passphrase = prompt.secret('Passphrase: ', confirm=confirm)
    ret = Creds(user_id, passphrase)
    return ret


def _get_creds(kf,
               user=None,
               interactive=True,
               check_env=True,
               passphrase_file=None,
               user_env_var='PPROTECT_USER',
               pass_env_var='PPROTECT_PASSPHRASE'):
    if not interactive and not check_env:
        raise UsageError('expected at least one of check_env'
                         ' and interactive to be True', 2)
    user_source = 'argument'
    passphrase, passphrase_source = None, None
    if passphrase_file:
        passphrase_file = os.path.abspath(passphrase_file)
        try:
            passphrase = open(passphrase_file, 'rb').read().decode('utf8')
        except IOError as ioe:
            if getattr(ioe, 'strerror', None):
                msg = '%s while reading passphrase from file at "%s"' % (ioe.strerror, passphrase_file)
            else:
                msg = 'Failed to read passphrase from file at "%s"' % passphrase_file
            raise UsageError(msg=msg)
        else:
            passphrase_source = "passphrase file: %s" % passphrase_file
    if user is None and user_env_var:
        user = os.getenv(user_env_var)
        user_source = 'env var: %s' % user_env_var
    if passphrase is None and pass_env_var:
        passphrase = os.getenv(pass_env_var)
        passphrase_source = 'env var: %s' % pass_env_var

    if interactive:
        if user is None:
            user = prompt('User email: ')
            user_source = 'stdin'
        if passphrase is None:
            passphrase = prompt.secret('Passphrase: ', confirm=False)
            passphrase_source = 'stdin'

    creds = Creds(_get_text(user), _get_text(passphrase),
                  name_source=user_source, passphrase_source=passphrase_source)
    _check_creds(kf, creds)

    return creds


def _check_creds(kf, creds):
    if kf.check_creds(creds):
        return True

    msg = 'Invalid user email'
    if creds.name_source:
        msg += ' (from %s)' % creds.name_source
    msg += ' or passphrase'
    if creds.passphrase_source:
        msg += ' (from %s)' % creds.passphrase_source
    msg += '. Check credentials and try again.'
    empty_fields = []
    if creds.name == '':
        empty_fields.append('user ID')
    if creds.passphrase == '':
        empty_fields.append('passphrase')
    if empty_fields:
        msg += ' (Warning: Empty ' + ' and '.join(empty_fields) + '.)'

    raise UsageError(msg, 1)


def _get_cmd(prepare=False):
    cmd = Command(name='pocket_protector', func=None, doc=__doc__)  # func=None means output help

    # add flags
    cmd.add('--file', missing='protected.yaml',
            doc='path to the PocketProtector-managed file, defaults to protected.yaml in the working directory')
    cmd.add('--confirm', parse_as=True,
            doc='show diff and prompt for confirmation before modifying the file')
    cmd.add('--non-interactive', parse_as=True,
            doc='disable falling back to interactive authentication, useful for automation')
    cmd.add('--ignore-env', parse_as=True, display=False,  # TODO: keep?
            doc='ignore environment variables like PPROTECT_PASSPHRASE')
    cmd.add('--user', char='-u',
            doc="the acting user's email credential")
    cmd.add('--passphrase-file',
            doc='path to a file containing only the passphrase, likely provided by a deployment system')

    # add middlewares, outermost first ("first added, first called")
    cmd.add(mw_verify_creds)
    cmd.add(mw_write_kf)
    cmd.add(mw_ensure_kf)
    cmd.add(mw_exit_handler)

    # add subcommands
    cmd.add(add_key_custodian, name='init', doc='create a new protected')
    cmd.add(add_key_custodian)

    cmd.add(add_domain)
    cmd.add(rm_domain)

    cmd.add(add_owner)
    cmd.add(rm_owner)

    cmd.add(add_secret)
    cmd.add(update_secret)
    cmd.add(rm_secret)

    cmd.add(set_key_custodian_passphrase)
    cmd.add(rotate_domain_keys)

    cmd.add(decrypt_domain, posargs={'count': 1, 'provides': 'domain_name'})

    cmd.add(list_domains)
    cmd.add(list_domain_secrets, posargs={'count': 1, 'provides': 'domain_name'})
    cmd.add(list_all_secrets)
    cmd.add(list_audit_log)

    cmd.add(print_version, name='version')

    if prepare:
        cmd.prepare()  # an optional check on all subcommands, not just the one being executed

    return cmd


def main(argv=None):  # pragma: no cover  (see note in tests.test_cli.test_main)
    cmd = _get_cmd()

    cmd.run(argv=argv)  # exit behavior is handled by mw_exit_handler

    return


"""
The following subcommand handlers all update/write to a protected file (wkf).
"""

def add_key_custodian(wkf):
    'add a new key custodian to the protected'
    echo('Adding new key custodian.')
    creds = _get_new_creds()
    return wkf.add_key_custodian(creds)


def add_domain(wkf, creds):
    'add a new domain to the protected'
    echo('Adding new domain.')
    domain_name = prompt('Domain name: ')

    return wkf.add_domain(domain_name, creds.name)


def rm_domain(wkf):
    'remove a domain and all of its keys from the protected'
    echo('Removing domain.')
    domain_name = prompt('Domain name: ')
    return wkf.rm_domain(domain_name)


def add_owner(wkf, creds):
    'add a key custodian to the owner list of a specific domain'
    echo('Adding domain owner.')
    domain_name = prompt('Domain name: ')
    new_owner_name = prompt('New owner email: ')
    return wkf.add_owner(domain_name, new_owner_name, creds)


def rm_owner(wkf):
    'remove a key custodian from the owner list of a domain'
    echo('Removing domain owner.')
    domain_name = prompt('Domain name: ')
    owner_name = prompt('Owner email: ')
    return wkf.rm_owner(domain_name, owner_name)


def add_secret(wkf):
    'add a secret to a domain'
    echo('Adding secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    secret_value = prompt('Secret value: ')
    return wkf.add_secret(domain_name, secret_name, secret_value)


def update_secret(wkf):
    'update a secret value in a domain'
    echo('Updating secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    secret_value = prompt('Secret value: ')
    return wkf.update_secret(domain_name, secret_name, secret_value)


def rm_secret(wkf):
    'remove a secret from a domain'
    echo('Updating secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    return wkf.rm_secret(domain_name, secret_name)


def set_key_custodian_passphrase(wkf):
    'update a key custodian passphrase'
    user_id = prompt('User email: ')
    passphrase = prompt.secret('Current passphrase: ')
    creds = Creds(user_id, passphrase)
    _check_creds(wkf, creds)
    new_passphrase = prompt.secret('New passphrase: ', confirm=True)
    return wkf.set_key_custodian_passphrase(creds, new_passphrase)


def rotate_domain_keys(wkf, creds):
    'rotate the internal encryption keys for a given domain'
    domain_name = prompt('Domain name: ')
    return wkf.rotate_domain_key(domain_name, creds)


"""
Read-only operations follow
"""

def print_version():
    'print the PocketProtector version and exit'
    echo('pocket_protector version %s' % __version__)
    sys.exit(0)


def decrypt_domain(kf, creds, domain_name):
    'output the decrypted contents of a domain in JSON format'
    decrypted_dict = kf.decrypt_domain(domain_name, creds)
    echo(json.dumps(decrypted_dict, indent=2, sort_keys=True))
    return 0


def list_domains(kf):
    'print a list of domain names, if any'
    domain_names = kf.get_domain_names()
    if domain_names:
        echo('\n'.join(domain_names))
    else:
        echo.err('(No domains in protected at %s)' % kf.path)
    return


def list_domain_secrets(kf, domain_name):
    'print a list of secret names for a given domain'
    secret_names = kf.get_domain_secret_names(domain_name)
    if secret_names:
        echo('\n'.join(secret_names))
    else:
        echo.err('(No secrets in domain %r of protected at %s)'
                 % (domain_name, kf.path))
    return


def list_all_secrets(kf):
    'print a list of all secret names, along with the domains that define each'
    secrets_map = kf.get_all_secret_names()
    if not secrets_map:
        echo.err('(No secrets in protected at %s)' % kf.path)
    else:
        for secret_name in sorted(secrets_map):
            domain_names = sorted(set(secrets_map[secret_name]))
            echo('%s: %s' % (secret_name, ', '.join(domain_names)))
    return


def list_audit_log(kf):
    'print a list of actions from the audit log, one per line'
    log_list = kf.get_audit_log()
    echo('\n'.join(log_list))
    return


"""
End subcommand handlers

Begin middlewares
"""


@face_middleware(provides=['creds'], optional=True)
def mw_verify_creds(next_, kf, user, ignore_env, non_interactive, passphrase_file):
    creds = _get_creds(kf, user,
                       check_env=not ignore_env,
                       interactive=not non_interactive,
                       passphrase_file=passphrase_file)
    return next_(creds=creds)


@face_middleware(provides=['kf'], optional=True)
def mw_ensure_kf(next_, file, subcmds_):
    file_path = file or 'protected.yaml'
    file_abs_path = os.path.abspath(file_path)
    init_kf = subcmds_[0] == 'init'
    if init_kf:
        kf = _create_protected(file_abs_path)
    else:
        kf = _ensure_protected(file_abs_path)

    try:
        ret = next_(kf=kf)
    except:
        if init_kf:
            try:
                os.unlink(file_abs_path)
            except Exception:
                echo.err('Warning: failed to remove file: %s' % file_abs_path)
        raise

    return ret


@face_middleware(provides=['wkf'], optional=True)
def mw_write_kf(next_, kf, confirm):
    if not os.access(kf.path, os.W_OK):
        raise UsageError('expected %r to be a writable file. Check the'
                         ' permissions and try again.' % kf.path)

    modified_kf = next_(wkf=kf)

    if not modified_kf:
        return modified_kf

    if confirm:
        diff_lines = list(difflib.unified_diff(kf.get_contents().splitlines(),
                                               modified_kf.get_contents().splitlines(),
                                               kf.path + '.old', kf.path + '.new'))
        diff_lines = _get_colorized_lines(diff_lines)
        echo('Changes to be written:\n')
        echo('\n'.join(diff_lines) + '\n')
        do_write = prompt('Write changes? [y/N] ')
        if not do_write.lower().startswith('y'):
            echo('Aborting...')
            sys.exit(0)

    modified_kf.write()

    return


@face_middleware
def mw_exit_handler(next_):
    status = 55  # should always be set to something else
    try:
        try:
            status = next_() or 0
        except PPError as ppe:
            raise UsageError(ppe.args[0])
    except KeyboardInterrupt:
        echo('')
        status = 130
    except EOFError:
        echo('')
        status = 1

    sys.exit(status)

    return
