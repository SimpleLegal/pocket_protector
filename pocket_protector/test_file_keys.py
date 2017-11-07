import file_keys

import tempfile

def test_file_keys():
    bob_creds = file_keys.Creds('bob@example.com', 'super-secret')
    alice_creds = file_keys.Creds('alice@example.com', 'super-duper-secret')

    tmp = tempfile.NamedTemporaryFile()
    test = file_keys.KeyFile(path=tmp.name)
    test = test.with_new_key_custodian(bob_creds)
    test = test.with_new_domain('new_domain', bob_creds.name)
    test = test.with_secret('new_domain', 'hello', 'world')
    test = test.with_new_key_custodian(alice_creds)
    test = test.with_owner('new_domain', alice_creds.name, bob_creds)
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
