# -*- coding: utf-8 -*-

#from __future__ import unicode_literals

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
SECRET_NAME = 'secret-name'
SECRET_VALUE = u'secrët-value'


def test_cli(tmp_path):
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)

    assert cc.run('pprotect version').stdout.startswith('pocket_protector version')

    protected_path = str(tmp_path) + '/protected.yaml'

    res = cc.run('pprotect init --file %s' % protected_path,
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert res.exit_code == 0

    file_data = ruamel.yaml.YAML().load(open(protected_path).read())
    assert list(file_data['key-custodians'])[0] == KURT_EMAIL
    assert len(file_data['audit-log']) == 1

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=tmp_path, env=kurt_env, reraise=True)

    res = cc.run(['pprotect', 'add-domain'], input=['first-domain'])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'add-secret'],
                 input=['first-domain', SECRET_NAME, SECRET_VALUE])
    assert res.exit_code == 0

    res = cc.run(['pprotect', 'decrypt-domain', 'first-domain'])
    assert res.exit_code == 0
    res_data = json.loads(res.stdout)
    assert res_data[SECRET_NAME] == SECRET_VALUE

    res = cc.run(['pprotect', 'decrypt-domain', 'nonexistent-domain'])
    assert res.exit_code == 1

    # test mixed env var and entry
    res = cc.run(['pprotect', 'decrypt-domain', 'first-domain'],
                 env={'PPROTECT_PASSPHRASE': None},
                 input=[KURT_PHRASE])
    assert res.exit_code == 0
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


    # test bad creds
    res = cc.run(['pprotect', 'decrypt-domain', 'first-domain'],
                 env={'PPROTECT_PASSPHRASE': 'nope'})
    assert res.exit_code == 1
