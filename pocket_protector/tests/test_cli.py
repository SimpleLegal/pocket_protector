# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import json
import ruamel.yaml

from face import CommandChecker

from pocket_protector import cli


def test_prepare():
    # confirms that all subcommands compile together nicely
    assert cli._get_cmd(prepare=True)
    return

KURT_EMAIL = 'kurt@example.com'
KURT_PHRASE = u'passphrasë'
MH_EMAIL = 'mahmoud@hatnote.com'
MH_PHRASE = 'thegame'
DOMAIN_NAME = 'first-domain'
SECRET_NAME = 'secret-name'
SECRET_VALUE = u'secrët-value'


# _fast_crypto from conftest
def test_cli(tmp_path, _fast_crypto):
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)

    assert cc.run('pprotect version').stdout.startswith('pocket_protector version')

    tmp_path = str(tmp_path)
    protected_path = tmp_path + '/protected.yaml'

    # fail init and ensure that file isn't created
    res = cc.run('pprotect init --file %s' % protected_path,
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE + 'nope'])
    assert res.exit_code == 1
    assert not os.path.exists(protected_path)

    res = cc.run('pprotect init --file %s' % protected_path,
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert res.exit_code == 0

    # check we can only create it once
    res = cc.run('pprotect init --file %s' % protected_path,
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert res.exit_code == 2

    file_data = ruamel.yaml.YAML().load(open(protected_path).read())
    assert list(file_data['key-custodians'])[0] == KURT_EMAIL
    assert len(file_data['audit-log']) == 1

    res = cc.run('pprotect list-audit-log --file %s' % protected_path)
    assert res.exit_code == 0
    assert len(res.stdout.splitlines()) == 1

    # make a new cc, with env and tmp_path baked in (also tests
    # protected.yaml in the cur dir being the default file)
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=tmp_path, env=kurt_env, reraise=True)

    res = cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'list_domains'])
    assert res.exit_code == 0
    assert res.stdout.splitlines() == [DOMAIN_NAME]

    res = cc.run(['pprotect', 'add-secret'],
                 input=[DOMAIN_NAME, SECRET_NAME, 'tmpval'])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'update-secret'],
                 input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'list-domain-secrets', DOMAIN_NAME])
    assert res.exit_code == 0
    assert res.stdout == SECRET_NAME + '\n'

    res = cc.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert res.exit_code == 0
    res_data = json.loads(res.stdout)
    assert res_data[SECRET_NAME] == SECRET_VALUE

    res = cc.run(['pprotect', 'decrypt-domain', 'nonexistent-domain'])
    assert res.exit_code == 1

    # already exists
    res = cc.run('pprotect add-key-custodian', input=[KURT_EMAIL, ''])
    assert res.exit_code == 1

    res = cc.run('pprotect add-key-custodian', input=[MH_EMAIL, MH_PHRASE, MH_PHRASE])
    assert res.exit_code == 0

    res = cc.run('pprotect add-owner', input=[DOMAIN_NAME, MH_EMAIL])
    assert res.exit_code == 0

    # missing protected
    res = cc.run('pprotect list-all-secrets', chdir=tmp_path + '/..')
    assert res.exit_code == 2

    res = cc.run('pprotect list-all-secrets')
    assert SECRET_NAME in res.stdout

    res = cc.run(['pprotect', 'rotate_domain_keys'], input=[DOMAIN_NAME])
    assert res.exit_code == 0

    # test mixed env var and entry
    res = cc.run(['pprotect', 'decrypt-domain', DOMAIN_NAME],
                 env={'PPROTECT_USER': MH_EMAIL, 'PPROTECT_PASSPHRASE': None},
                 input=[MH_PHRASE])
    assert res.exit_code == 0
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE

    # test bad creds
    res = cc.run(['pprotect', 'decrypt-domain', DOMAIN_NAME],
                 env={'PPROTECT_USER': None, 'PPROTECT_PASSPHRASE': 'nope'},
                 input=[KURT_EMAIL])
    assert res.exit_code == 1

    res = cc.run('pprotect set-key-custodian-passphrase',
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE, KURT_PHRASE + 'nope'])
    assert res.exit_code == 1
    assert 'did not match' in res.stdout  # TODO: may change to stderr

    # correctly reset passphrase
    new_kurt_phrase = KURT_PHRASE + 'yep'
    res = cc.run('pprotect set-key-custodian-passphrase',
                 input=[KURT_EMAIL, KURT_PHRASE, new_kurt_phrase, new_kurt_phrase])
    assert res.exit_code == 0

    # try new passphrase with a passphrase file why not
    ppfile_path = str(tmp_path) + 'tmp_passphrase'
    with open(ppfile_path, 'wb') as f:
        f.write(new_kurt_phrase.encode('utf8'))
    res = cc.run(['pprotect', 'decrypt-domain', '--non-interactive',
                  '--passphrase-file', ppfile_path, DOMAIN_NAME])
    assert res.exit_code == 0
    res_data = json.loads(res.stdout)
    assert res_data[SECRET_NAME] == SECRET_VALUE

    # test removals
    res = cc.run(['pprotect', 'rm-owner'], input=[DOMAIN_NAME, MH_EMAIL])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'rm-secret'], input=[DOMAIN_NAME, SECRET_NAME])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'rm-domain', '--confirm'], input=[DOMAIN_NAME, 'y'])
    assert res.exit_code == 0
