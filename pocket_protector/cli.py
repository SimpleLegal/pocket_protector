# -*- coding: utf-8 -*-

import os
import sys
import json
import getpass
import difflib
import argparse

from file_keys import KeyFile, Creds

_ANSI_FORE_RED = '\x1b[31m'
_ANSI_FORE_GREEN = '\x1b[32m'
_ANSI_RESET_ALL = '\x1b[0m'

# TODO: custodian-signed values. allow custodians to sign values
# added/set by others, then produced reports on which keys have been
# updated/changed but not signed yet. enables a review/audit mechanism.

def get_argparser():
    """
    args:

    path to file
    confirm-diff

    actions:

    init - done
    add key custodian - done
    add domain - done
    add owner - done
    set secret - done
    set key custodian passphrase - done
    remove key custodian - needs backend
    remove domain - needs backend
    remove owner - needs backend
    remove secret - needs backend
    truncate audit log - needs backend
    rotate key domain keypair - done
    rotate key custodian keypair - done
    # both rotations require creds but externally-used creds (passphrases) stay the same

    read-only:

    list domains
    list all keys (with list of domains with the key)

    # TODO: flag for not confirming password (for rotation)
    # TODO: flag for username on the commandline (-u)
    """
    prs = argparse.ArgumentParser()
    prs.add_argument('--file',
                     help='the file to pocket protect, defaults to protected.yaml in the working directory')
    prs.add_argument('--confirm-diff', action='store_true',
                     help='show diff before modifying the file')
    prs.add_argument('--non-interactive', action='store_true',
                     help='disable falling back to user input, useful for automation')
    subprs = prs.add_subparsers(dest='action')

    subprs.add_parser('init')
    subprs.add_parser('add-key-custodian')
    subprs.add_parser('add-domain')
    subprs.add_parser('add-owner')
    subprs.add_parser('set-secret')
    subprs.add_parser('set-key-custodian-passphrase')
    subprs.add_parser('decrypt-domain')

    return prs


class PPCLIError(Exception):
    def __init__(self, msg, exit_code=1):
        self.msg = msg
        self.exit_code = exit_code

        super(PPCLIError, self).__init__(msg)


def main(argv=None):
    argv = argv if argv is not None else sys.argv
    prs = get_argparser()
    args = prs.parse_args()

    try:
        ret = _main(args) or 0
    except KeyboardInterrupt:
        ret = 130
    except PPCLIError as ppce:
        if ppce.args:
            print '; '.join([str(a) for a in ppce.args])
        ret = ppce.exit_code

    sys.exit(ret)
    return


def _main(args):
    action = args.action
    confirm_diff = args.confirm_diff
    file_path = args.file or 'protected.yaml'
    file_abs_path = os.path.abspath(file_path)

    if action == 'init':
        if os.path.exists(file_abs_path):
            raise PPCLIError('File already exists: %s' % file_abs_path, 2)
            #print(
            #sys.exit(2)
        with open(file_abs_path, 'wb') as f:
            f.write('')  # TODO
            # TODO: automatically remove file if init fails
        kf = KeyFile(path=file_abs_path)
        # TODO: add audit log entry for creation date
        # TODO: add audit log dates in general
    else:
        if not os.path.exists(file_abs_path):
            print('File not found: %s' % file_path)
            sys.exit(2)
        kf = KeyFile.from_file(file_abs_path)
    modified_kf = None

    if action == 'init' or action == 'add-key-custodian':
        print 'Adding new key custodian.'
        creds = get_creds(confirm_pass=True)
        modified_kf = kf.add_key_custodian(creds)
    elif action == 'add-domain':
        print 'Adding new domain.'
        creds = check_creds(kf, get_creds())
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.add_domain(domain_name, creds.name)
    elif action == 'set-secret':
        print 'Setting secret value.'
        domain_name = raw_input('Domain name: ')
        secret_name = raw_input('Secret name: ')
        secret_value = raw_input('Secret value: ')  # TODO: getpass?
        modified_kf = kf.set_secret(domain_name, secret_name, secret_value)
    elif action == 'add-owner':
        print 'Adding domain owner.'
        creds = check_creds(kf, get_creds())
        domain_name = raw_input('Domain name: ')
        new_owner_name = raw_input('New owner email: ')
        modified_kf = kf.add_owner(domain_name, new_owner_name, creds)
    elif action == 'set-key-custodian-passphrase':
        user_id = raw_input('User email: ')
        passphrase = get_pass(confirm_pass=False, label='Current passphrase')
        creds = Creds(user_id, passphrase)
        check_creds(kf, creds)
        new_passphrase = get_pass(confirm_pass=True,
                                  label='New passphrase',
                                  label2='Retype new passphrase')
        modified_kf = kf.set_key_custodian_passphrase(creds, new_passphrase)
    elif action == 'decrypt-domain':
        creds = check_creds(kf, get_creds())
        domain_name = raw_input('Domain name: ')
        decrypted_dict = kf.decrypt_domain(domain_name, creds)
        print json.dumps(decrypted_dict, indent=2, sort_keys=True)
    elif action == 'rotate-domain-key':
        creds = check_creds(kf, get_creds())
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.rotate_domain_key(domain_name, creds)
    elif action == 'rotate-key-custodian-key':
        creds = check_creds(kf, get_creds())
        modified_kf = kf.rotate_key_custodian_key(creds)
    else:
        raise NotImplementedError('Unrecognized subcommand: %s' % action)

    if confirm_diff:
        diff_lines = list(difflib.unified_diff(kf.get_contents().splitlines(),
                                               modified_kf.get_contents().splitlines(),
                                               file_path + '.old', file_path + '.new'))
        diff_lines = _get_colorized_lines(diff_lines)
        print 'Changes to be written:\n'
        print '\n'.join(diff_lines)
        print
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


def check_creds(kf, creds):
    if not kf.check_creds(creds):
        msg = 'Invalid user credentials. Check email and passphrase and try again.'
        empty_fields = []
        if creds.user == '':
            empty_fields.append('user ID')
        if creds.passphrase == '':
            empty_fields.append('passphrase')
        if empty_fields:
            msg += ' Warning: Empty ' + ' and '.join('empty_fields') + '.'
        sys.exit(1)
    return creds


def get_creds(confirm_pass=False):
    user_id = raw_input('User email: ')
    passphrase = get_pass(confirm_pass=confirm_pass)
    ret = Creds(user_id, passphrase)
    return ret


def get_pass(confirm_pass=False, label='Passphrase', label2='Retype passphrase'):
    passphrase = getpass.getpass('%s: ' % label)
    if confirm_pass:
        passphrase2 = getpass.getpass('%s: ' % label2)
        if passphrase != passphrase2:
            print 'Sorry, passphrases did not match.'
            sys.exit(1)
    return passphrase


def full_get_creds(user=None,
                   interactive=True,
                   check_kf=None,
                   user_env_var='PPROTECT_USER',
                   pass_env_var='PPROTECT_PASS'):
    if not user and user_env_var:
        user = os.getenv(user_env_var)
    if pass_env_var:
        passphrase = os.getenv(pass_env_var)

    if interactive:
        if user is None:
            user = raw_input('User email: ')
        if passphrase is None:
            passphrase = get_pass(confirm_pass=False)

    creds = Creds(user, passphrase)

    if check_kf and not check_kf.check_creds(creds):
        msg = 'Invalid user credentials. Check email and passphrase and try again.'
        empty_fields = []
        if creds.user == '':
            empty_fields.append('user ID')
        if creds.passphrase == '':
            empty_fields.append('passphrase')
        if empty_fields:
            msg += ' Warning: Empty ' + ' and '.join('empty_fields') + '.'
        sys.exit(1)

    return creds


if __name__ == '__main__':
    sys.exit(main(sys.argv) or 0)
