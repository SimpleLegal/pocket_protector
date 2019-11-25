from __future__ import print_function
from __future__ import unicode_literals

import io
import os

import attr
import pytest

import cli


@attr.s(frozen=True)
class PProtect(object):
    path = attr.ib()


@pytest.fixture
def pprotect(monkeypatch, tmp_path):
    os.chdir(str(tmp_path))
    # fake_stdin = io.StringIO('user@example.com\n')
    monkeypatch.setattr('sys.stdin', io.StringIO('user@example.com\n'))
    monkeypatch.setattr('getpass.getpass', lambda x: 'pass')
    os.environ['PPROTECT_USER'] = 'user@example.com'
    os.environ['PPROTECT_PASS'] = 'pass'
    cli.main(['testing', 'init'])
    return PProtect(
        path=tmp_path,
    )


def test_pprotect(pprotect):
    assert os.path.exists('protected.yaml')


def test_add_secret(pprotect, monkeypatch):
    monkeypatch.setattr('sys.stdin', io.StringIO('mydomain\n'))
    cli.main(['testing', 'add-domain'])
