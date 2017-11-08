# -*- coding: utf-8 -*-

import file_keys

import tempfile


def test_file_keys():
    bob_creds = file_keys.Creds('bob@example.com', 'super-secret')
    alice_creds = file_keys.Creds('alice@example.com', 'super-duper-secret')
    def chk(fk):
        assert fk.from_contents_and_path(fk.get_contents(), fk._path) == fk

    tmp = tempfile.NamedTemporaryFile()
    test = file_keys.KeyFile(path=tmp.name)
    chk(test)
    test = test.add_key_custodian(bob_creds)
    chk(test)
    test = test.add_domain('new_domain', bob_creds.name)
    chk(test)
    test = test.set_secret('new_domain', 'hello', 'world')
    chk(test)
    test = test.add_key_custodian(alice_creds)
    chk(test)
    test = test.add_owner('new_domain', alice_creds.name, bob_creds)
    chk(test)
    test = test.rotate_key_custodian_key(bob_creds)
    chk(test)
    test = test.set_key_custodian_passphrase(bob_creds, 'super-extra-secret')
    test.write()
    round_trip = file_keys.KeyFile.from_file(test._path)
    assert round_trip == test
    print "generated file:"
    print open(test._path).read()
    print "..."


if __name__ == "__main__":
    try:
        test_file_keys()
    except:
        import pdb
        import traceback
        traceback.print_exc()
        pdb.post_mortem()
