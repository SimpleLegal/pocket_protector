# -*- coding: utf-8 -*-

import os
import sys
import getpass
import argparse

from file_keys import KeyFile, Creds


def get_argparser():
    """
    args:

    path to file
    dry run (shows diff)

    actions:

    add key custodian
    add domain
    add owner
    set secret
    set key custodian passphrase
    remove key custodian
    remove domain
    remove owner
    remove secret
    truncate audit log
    init/create_protected?

    read-only:

    list domains
    list all keys (with list of domains with the key)

    # TODO: AtomicSaver
    """
    prs = argparse.ArgumentParser()
    prs.add_argument('--file')
    prs.add_argument('--dry-run', action='store_true', help='TBI: show diff instead of writing changes to file')
    # TODO: confirm-changes instead of dry-run? due to the amount of user interaction
    subprs = prs.add_subparsers(dest='action')

    subprs.add_parser('init')
    subprs.add_parser('add_key_custodian')
    subprs.add_parser('add_domain')
    subprs.add_parser('add_owner')
    subprs.add_parser('set_secret')
    subprs.add_parser('set_key_custodian_passphrase')

    return prs


def main(argv=None):
    argv = argv if argv is not None else sys.argv
    prs = get_argparser()

    kwargs = dict(prs.parse_args()._get_kwargs())
    action = kwargs['action']
    file_path = kwargs.get('file') or 'protected.yaml'
    file_abs_path = os.path.abspath(file_path)

    if action == 'init':
        if os.path.exists(file_abs_path):
            print('file already exists: %s' % file_abs_path)
            return 2
        with open(file_abs_path, 'wb') as f:
            f.write('')  # TODO
            # TODO: automatically remove file if init fails
        kf = KeyFile(path=file_abs_path)
        # TODO: add audit log entry for creation date
        # TODO: add audit log dates in general
    else:
        if not os.path.exists(file_abs_path):
            print('no such file: %s' % file_path)
        kf = KeyFile.from_file(file_abs_path)
    modified_kf = None

    if action == 'init' or action == 'add_key_custodian':
        print 'Adding new key custodian.'
        creds = get_creds(confirm_pass=True)
        modified_kf = kf.add_key_custodian(creds)
    elif action == 'add_domain':
        print 'Adding new domain.'
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        modified_kf = kf.add_domain(domain_name, creds.name)
    elif action == 'set_secret':
        print 'Setting secret value.'
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        secret_name = raw_input('Secret name: ')
        secret_value = raw_input('Secret value: ')  # TODO: getpass?
        modified_kf = kf.set_secret(domain_name, secret_name, secret_value)
    elif action == 'add_owner':
        print 'Adding domain owner.'
        creds = get_creds()
        domain_name = raw_input('Domain name: ')
        # TODO ?
    elif action == 'set_key_custodian_passphrase':
        user_id = raw_input('User ID: ')
        passphrase = get_pass(confirm_pass=False, label='Current passphrase')
        creds = Creds(user_id, passphrase)
        new_passphrase = get_pass(confirm_pass=True,
                                  label='New passphrase',
                                  label2='Retype new passphrase')
        modified_kf = kf.set_key_custodian_passphrase(creds, new_passphrase)
    else:
        raise NotImplementedError('Unrecognized subcommand: %s' % action)

    if kwargs['dry_run']:
        return 0  # TODO

    if modified_kf:
        modified_kf.write()

    return


def get_creds(confirm_pass=False):
    user_id = raw_input('User ID: ')
    passphrase = get_pass(confirm_pass=confirm_pass)
    return Creds(user_id, passphrase)


def get_pass(confirm_pass=False, label='Passphrase', label2='Retype passphrase'):
    passphrase = getpass.getpass('%s: ' % label)
    if confirm_pass:
        passphrase2 = getpass.getpass('%s: ' % label2)
        if passphrase != passphrase2:
            print 'Sorry, passphrases did not match.'
            sys.exit(1)
    return passphrase




if __name__ == '__main__':
    sys.exit(main(sys.argv) or 0)
