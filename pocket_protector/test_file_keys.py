# -*- coding: utf-8 -*-

import file_keys

import tempfile


def test_file_keys():
    bob_creds = file_keys.Creds('bob@example.com', 'super-secret')
    alice_creds = file_keys.Creds('alice@example.com', 'super-duper-secret')

    _prev = [None]
    def chk(fk):
        assert fk.from_contents_and_path(fk.get_contents(), fk._path) == fk
        assert _prev[0] != fk, "function call resulted in no changes to data"
        _prev[0] = fk

    tmp = tempfile.NamedTemporaryFile()
    test1 = test = file_keys.KeyFile(path=tmp.name)
    chk(test)
    test2 = test = test.add_key_custodian(bob_creds)
    chk(test)
    test3 = test = test.add_domain('new_domain', bob_creds.name)
    chk(test)
    test4 = test = test.set_secret('new_domain', 'hello', 'world')
    chk(test)
    assert test.decrypt_domain('new_domain', bob_creds)['hello'] == 'world'
    test5 = test = test.set_secret('new_domain', 'hello', 'better-world')
    chk(test)
    assert test.decrypt_domain('new_domain', bob_creds)['hello'] == 'better-world'
    test6 = test = test.add_key_custodian(alice_creds)
    chk(test)
    test7 = test = test.add_owner('new_domain', alice_creds.name, bob_creds)
    chk(test)
    test8 = _test = test.rm_owner('new_domain', alice_creds.name)
    chk(_test)  # throw away this mutation
    test9 = _test = test.rm_key_custodian(alice_creds.name)
    chk(_test)  # throw away this mutation
    before_rotate = test.decrypt_domain('new_domain', bob_creds)
    test10 = test = test.rotate_domain_key('new_domain', bob_creds)
    chk(test)
    assert test.decrypt_domain('new_domain', bob_creds) == before_rotate
    test11 = test = test.rotate_key_custodian_key(bob_creds)
    chk(test)
    test12 = test = test.set_key_custodian_passphrase(bob_creds, 'super-extra-secret')
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
 