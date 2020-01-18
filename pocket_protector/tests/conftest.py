
import nacl
import pytest
import pocket_protector.file_keys

@pytest.fixture
def _fast_crypto():
    old_opslimit = pocket_protector.file_keys.OPSLIMIT
    old_memlimit = pocket_protector.file_keys.MEMLIMIT

    pocket_protector.file_keys.OPSLIMIT = nacl.pwhash.OPSLIMIT_MIN
    pocket_protector.file_keys.MEMLIMIT = nacl.pwhash.MEMLIMIT_MIN

    yield

    pocket_protector.file_keys.OPSLIMIT = old_opslimit
    pocket_protector.file_keys.MEMLIMIT = old_memlimit
    return
