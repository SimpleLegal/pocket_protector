
import os
import imp
from setuptools import setup, find_packages

__author__ = "Kurt Rose and Mahmoud Hashemi"
__contact__ = "kurt@kurtrose.com"
__license__ = 'Apache License 2.0'

CUR_PATH = os.path.abspath(os.path.dirname(__file__))
_version_mod_path = os.path.join(CUR_PATH, 'pocket_protector', '_version.py')
_version_mod = imp.load_source('_version', _version_mod_path)
__version__ = _version_mod.__version__

setup(
    name="pocket-protector",
    description="Handy secret management system with a convenient CLI and readable storage format.",
    author=__author__,
    author_email=__contact__,
    license=__license__,
    platforms='any',
    version=__version__,
    long_description=__doc__,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={'console_scripts': ['pprotect = pocket_protector.__main__:main',
                                      'pocket_protector = pocket_protector.__main__:main']},
    install_requires=['attrs',
                      'boltons',
                      'PyNaCl',
                      'ruamel.yaml',
                      'schema']
)

"""
Release process:

* tox
* git commit (if applicable)
* Remove dev suffix from pocket_protector/_version.py version
* git commit -a -m "bump version for vX.Y.Z release"
* python setup.py sdist bdist_wheel upload
* git commit
* git tag -a vX.Y.Z -m "brief summary"
* write CHANGELOG
* git commit
* bump pocket_protector/_version.py version onto n+1 dev
* git commit
* git push

Versions are of the format YY.MINOR.MICRO, see calver.org for more details.
"""
