
"""
Things a face client should manage:

* os.chdir into a working dir?

"""
import ruamel.yaml

from face import CommandChecker

from pocket_protector import cli

def test_prepare():
    # confirms that all subcommands compile together nicely
    assert cli._get_cmd(prepare=True)
    return


def test_cli(tmp_path):
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)

    protected_path = str(tmp_path) + '/protected.yaml'

    res = cc.run('pprotect init --file %s' % protected_path,
                 input=['kurt@example.com', 'passphrase', 'passphrase'])
    assert res.exit_code == 0

    file_data = ruamel.yaml.YAML().load(open(protected_path).read())
    assert list(file_data['key-custodians'])[0] == 'kurt@example.com'
    assert len(file_data['audit-log']) == 1
