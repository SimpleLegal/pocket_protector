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

_GLOBAL_ARG_MAP = {'file': {'help': 'the file to pocket protect, defaults to protected.yaml in the working directory'},
                   'confirm-diff': {'action': 'store_true', 'help': 'show diff before modifying the file'},
                   'non-interactive': {'action': 'store_true', 'help': 'disable falling back to interactive authentication, useful for automation'},
                   'user': {'short_form': 'u', 'help': "the acting user's email credential"}}

_INTERACTIVE_ARGS = ['file', 'confirm-diff', 'user']
_NON_INTERACTIVE_ARGS = _INTERACTIVE_ARGS + ['non-interactive']

_SUBCMDS = [('init',
             {'help': 'create a new pocket-protected file',
              'args': ['file', 'non-interactive', 'user']}),
            ('add-key-custodian',
             {'help': 'add a new key custodian to the protected',
              'args': _INTERACTIVE_ARGS}),
            ('add-domain',
             {'help': 'add a new domain to the protected',
              'args': _INTERACTIVE_ARGS}),
            ('rm-domain',
             {'help': 'remove a domain from the protected',
              'args': _INTERACTIVE_ARGS}),
            ('add-owner',
             {'help': 'add a key custodian as owner of a domain',
              'args': _INTERACTIVE_ARGS}),
            ('rm-owner',
             {'help': "remove an owner's privileges on a specified domain",
              'args': _INTERACTIVE_ARGS}),
            ('add-secret',
             {'help': 'add a secret to a specified domain',
              'args': _INTERACTIVE_ARGS}),
            ('update-secret',
             {'help': 'update an existing secret in a specified domain',
              'args': _INTERACTIVE_ARGS}),
            ('rm-secret',
             {'help': 'remove a secret from a specified domain',
              'args': _INTERACTIVE_ARGS}),
            ('set-key-custodian-passphrase',
             {'help': 'change a key custodian passphrase',
              'args': _INTERACTIVE_ARGS}),
            ('decrypt-domain',
             {'help': 'decrypt and display JSON-formatted cleartext for a domain',
              'args': _NON_INTERACTIVE_ARGS}),
            ('rotate-key-custodian-keys',
             {'help': 'rotate the internal keys used to protect key custodian keypairs',
              'args': _NON_INTERACTIVE_ARGS}),
            ('rotate-domain-keys',
             {'help': 'rotate the internal keys for a particular domain (must be owner)',
              'args': _NON_INTERACTIVE_ARGS})]
_SUBCMD_SET = set([x[0] for x in _SUBCMDS])

def _format_top_level_help(subcmds):
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
    for cmd_name, cmd_dict in subcmds:
        cmd_prs = subprs.add_parser(cmd_name, description=cmd_dict.get('help', ''))

    return prs.format_help()


def get_argparser():
    """
    TODO: read-only:

    list domains
    list all keys (with list of domains with the key)
    list keys accessible by X
    """
    prs = argparse.ArgumentParser()

    subprs = prs.add_subparsers(dest='action')
    subprs.add_parser('version')
    subprs_map = {}

    for subcmd_name, subcmd_dict in _SUBCMDS:
        subprs_map[subcmd_name] = subprs.add_parser(subcmd_name, help='')
        for arg in subcmd_dict['args']:
            arg_def = dict(_GLOBAL_ARG_MAP[arg])
            long_form = arg_def.pop('long_form', arg)
            short_form = arg_def.pop('short_form', None)
            a = ['--' + long_form]
            if short_form:
                a += ['-' + short_form]
            kw = arg_def
            subprs_map[subcmd_name].add_argument(*a, **kw)

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
    if (len(argv) > 1 and argv[1] not in _SUBCMD_SET) and ('-h' in argv or '--help' in argv):
        print _format_top_level_help(_SUBCMDS)
        sys.exit(0)
    prs = get_argparser()
    args = prs.parse_args(argv[1:])
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
    interactive = not args.non_interactive
    modified_kf = None

    # TODO
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
