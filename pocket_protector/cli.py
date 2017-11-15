# -*- coding: utf-8 -*-

import os
import sys
import json
import getpass
import difflib
import argparse

from _version import __version__
from file_keys import KeyFile, Creds

_ANSI_FORE_RED = '\x1b[31m'
_ANSI_FORE_GREEN = '\x1b[32m'
_ANSI_RESET_ALL = '\x1b[0m'

# TODO: custodian-signed values. allow custodians to sign values
# added/set by others, then produced reports on which keys have been
# updated/changed but not signed yet. enables a review/audit mechanism.

# TODO: translate all ValueErrors etc. raised from the backend to
# errors that are caught without displaying a stack trace

_SUBCMD_MAP = {'init': 'create a new pocket-protected file',
               'add-key-custodian': 'add a new key custodian to the protected',
               'add-domain': 'add a new domain to the protected',
               'rm-domain': 'remove a domain from the protected',
               'add-owner': 'add a key custodian as owner of a domain',
               'rm-owner': "remove an owner's privileges on a specified domain",
               'add-secret': 'add a secret to a specified domain',
               'update-secret': 'update an existing secret in a specified domain',
               'rm-secret': 'remove a secret from a specified domain',
               'set-key-custodian-passphrase': 'change a key custodian passphrase',
               'decrypt-domain': 'decrypt and display JSON-formatted cleartext for a domain',
               'rotate-key-custodian-keys': 'rotate the internal keys used to protect key custodian keypairs',
               'rotate-domain-keys': 'rotate the internal keys for a particular domain (must be owner)'}


def _format_top_level_help(cmd_map):
    class SubcommandArgumentParser(argparse.ArgumentParser):
        def __init__(self, *args, **kw):
            kw['formatter_class'] = SubcommandHelpFormatter
            argparse.ArgumentParser.__init__(self, *args, **kw)
            self._positionals.title = 'Commands'
            self._optionals.title = 'Options'
            self.usage = '%(prog)s [COMMANDS]'


    class SubcommandHelpFormatter(argparse.HelpFormatter):
        def add_arguments(self, actions):
            if not actions or not actions[0].choices:
                super(SubcommandHelpFormatter, self).add_arguments(actions)
                return
            new_actions = [argparse.Action((), dest=k, help=v.description)
                           for k, v in sorted(actions[0].choices.items(), key=lambda i: i[0])]
            super(SubcommandHelpFormatter, self).add_arguments(new_actions)

    prs = SubcommandArgumentParser(description="")

    subprs = prs.add_subparsers(dest='action')
    for cmd_name, cmd_desc in cmd_map.items():
        cmd_prs = subprs.add_parser(cmd_name, description=cmd_desc)

    return prs.format_help()


def get_argparser():
    """
    TODO: read-only:

    list domains
    list all keys (with list of domains with the key)
    list keys accessible by X
    """
    prs = argparse.ArgumentParser()
    global_args = [{'*': ['--file'],
                    'help': 'the file to pocket protect, defaults to protected.yaml in the working directory'},
                   {'*': ['--confirm-diff'],
                    'action': 'store_true',
                    'help': 'show diff before modifying the file'},
                   {'*': ['--non-interactive'],
                    'action': 'store_true',
                    'help': 'disable falling back to interactive authentication, useful for automation'},
                   {'*': ['-u', '--user'],
                    'help': 'the user email, where applicable'}]

    subprs = prs.add_subparsers(dest='action')
    subprs.add_parser('version')
    subprs_map = {}

    for subcmd_name in sorted(_SUBCMD_MAP.keys()):
        subprs_map[subcmd_name] = subprs.add_parser(subcmd_name)
        for arg_dict in global_args:
            arg_dict = dict(arg_dict)
            args = arg_dict.pop('*')
            subprs_map[subcmd_name].add_argument(*args, **arg_dict)

    return prs


class PPCLIError(Exception):
    def __init__(self, msg=None, exit_code=1):
        self.msg = msg
        self.exit_code = exit_code
        if msg:
            super(PPCLIError, self).__init__(msg)
        return


def main(argv=None):
    argv = argv if argv is not None else sys.argv
    if (len(argv) > 1 and argv[1] not in _SUBCMD_MAP) and ('-h' in argv or '--help' in argv):
        print _format_top_level_help(_SUBCMD_MAP)
        sys.exit(0)
    prs = get_argparser()
    args = prs.parse_args()
    action = args.action
    file_path = getattr(args, 'file', '') or 'protected.yaml'
    file_abs_path = os.path.abspath(file_path)

    try:
        if action == 'version':
            print('pocket_protector version %s' % __version__)
            sys.exit(0)
        elif action == 'init':
            kf = _create_protected(file_abs_path)
        else:
            kf = _ensure_protected(file_abs_path)

        try:
            ret = _main(kf, action, args) or 0
        except:
            if action == 'init':
                try:
                    os.unlink(file_abs_path)
                except Exception:
                    print 'Warning: failed to remove file: %s' % file_abs_path
            raise
    except KeyboardInterrupt:
        ret = 130
        print('')
    except EOFError:
        ret = 1
        print('')
    except PPCLIError as ppce:
        if ppce.args:
            print('; '.join([str(a) for a in ppce.args]))
        ret = ppce.exit_code

    sys.exit(ret)
    return


def _create_protected(path):
    if os.path.exists(path):
        raise PPCLIError('Protected file already exists: %s' % path, 2)
    open(path, 'wb').close()
    kf = KeyFile(path=path)
    # TODO: add audit log entry for creation date
    # TODO: add audit log dates in general
    kf.write()
    return kf


def _ensure_protected(path):
    if not os.path.exists(path):
        raise PPCLIError('Protected file not found: %s' % path, 2)
    kf = KeyFile.from_file(path)
    return kf


def _main(kf, action, args):
    confirm_diff = args.confirm_diff
    user = args.user
    modified_kf = None

    # TODO
    interactive = True
    check_env = True
    get_creds = lambda: _get_creds(kf, user, interactive=interactive, check_env=check_env)

    if action == 'init' or action == 'add-key-custodian':
        print 'Adding new key custodian.'
        creds = _get_new_creds()
        modified_kf = kf.add_key_custodian(creds)
    elif action == 'add-domain':
        print 'Adding new domain.'
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.add_domain(domain_name, creds.name)
    elif action == 'rm-domain':
        print 'Removing domain.'
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.rm_domain(domain_name)
    elif action == 'add-owner':
        print 'Adding domain owner.'
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        new_owner_name = raw_input('New owner email: ')
        modified_kf = kf.add_owner(domain_name, new_owner_name, creds)
    elif action == 'rm-owner':
        print 'Removing domain owner.'
        domain_name = raw_input('Domain name: ')
        owner_name = raw_input('Owner email: ')
        modified_kf = kf.rm_owner(domain_name, owner_name)
    elif action == 'add-secret':
        print 'Adding secret value.'
        domain_name = raw_input('Domain name: ')
        secret_name = raw_input('Secret name: ')
        secret_value = raw_input('Secret value: ')
        modified_kf = kf.add_secret(domain_name, secret_name, secret_value)
    elif action == 'update-secret':
        print 'Updating secret value.'
        domain_name = raw_input('Domain name: ')
        secret_name = raw_input('Secret name: ')
        secret_value = raw_input('Secret value: ')
        modified_kf = kf.update_secret(domain_name, secret_name, secret_value)
    elif action == 'rm-secret':
        print 'Removing secret value.'
        domain_name = raw_input('Domain name: ')
        secret_name = raw_input('Secret name: ')
        modified_kf = kf.rm_secret(domain_name, secret_name)
    elif action == 'set-key-custodian-passphrase':
        user_id = raw_input('User email: ')
        passphrase = _get_pass(confirm_pass=False, label='Current passphrase')
        creds = Creds(user_id, passphrase)
        _check_creds(kf, creds)
        new_passphrase = _get_pass(confirm_pass=True,
                                  label='New passphrase',
                                  label2='Retype new passphrase')
        modified_kf = kf.set_key_custodian_passphrase(creds, new_passphrase)
    elif action == 'decrypt-domain':
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        decrypted_dict = kf.decrypt_domain(domain_name, creds)
        print json.dumps(decrypted_dict, indent=2, sort_keys=True)
    elif action == 'rotate-domain-keys':
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.rotate_domain_key(domain_name, creds)
    elif action == 'rotate-key-custodian-keys':
        creds = get_creds()
        modified_kf = kf.rotate_key_custodian_key(creds)
    else:
        raise NotImplementedError('Unrecognized subcommand: %s' % action)

    if confirm_diff:
        diff_lines = list(difflib.unified_diff(kf.get_contents().splitlines(),
                                               modified_kf.get_contents().splitlines(),
                                               kf._path + '.old', kf._path + '.new'))
        diff_lines = _get_colorized_lines(diff_lines)
        print('Changes to be written:\n')
        print('\n'.join(diff_lines) + '\n')
        do_write = raw_input('Write changes? [y/N] ')
        if not do_write.lower().startswith('y'):
            print 'Aborting...'
            sys.exit(0)

    if modified_kf:
        modified_kf.write()

    return


def _get_colorized_lines(lines):
    ret = []
    colors = {'-': _ANSI_FORE_RED, '+': _ANSI_FORE_GREEN}
    for line in lines:
        if line[0] in colors:
            line = colors[line[0]] + line + _ANSI_RESET_ALL
        ret.append(line)
    return ret


def _check_creds(kf, creds, raise_exc=True):
    if not kf.check_creds(creds):
        msg = 'Invalid user credentials. Check email and passphrase and try again.'
        empty_fields = []
        if creds.name == '':
            empty_fields.append('user ID')
        if creds.passphrase == '':
            empty_fields.append('passphrase')
        if empty_fields:
            msg += ' Warning: Empty ' + ' and '.join('empty_fields') + '.'
        if raise_exc:
            raise PPCLIError(msg, 1)
        return False
    return True


def _get_new_creds(confirm_pass=True):
    user_id = raw_input('User email: ')
    passphrase = _get_pass(confirm_pass=confirm_pass)
    ret = Creds(user_id, passphrase)
    return ret


def _get_pass(confirm_pass=False, label='Passphrase', label2='Retype passphrase'):
    passphrase = getpass.getpass('%s: ' % label)
    if confirm_pass:
        passphrase2 = getpass.getpass('%s: ' % label2)
        if passphrase != passphrase2:
            print 'Sorry, passphrases did not match.'
            sys.exit(1)
    return passphrase


def _get_creds(kf,
               user=None,
               interactive=True,
               check_env=True,
               user_env_var='PPROTECT_USER',
               pass_env_var='PPROTECT_PASSPHRASE'):
    if not interactive and not check_env:
        raise RuntimeError('expected at least one of check_env'
                           ' and interactive to be True')
    if not user and user_env_var:
        user = os.getenv(user_env_var)
    if pass_env_var:
        passphrase = os.getenv(pass_env_var)

    if interactive:
        if user is None:
            user = raw_input('User email: ')
        if passphrase is None:
            passphrase = _get_pass(confirm_pass=False)

    creds = Creds(user, passphrase)
    _check_creds(kf, creds)

    return creds

    # Failed to read valid PocketProtector passphrase (for user XXX)
    # from stdin and <passphrase_env_var_name> was not set. (XYZError:
    # was not set)

if __name__ == '__main__':
    sys.exit(main(sys.argv) or 0)
