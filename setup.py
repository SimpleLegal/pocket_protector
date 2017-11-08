from setuptools import setup, find_packages

__author__ = "Kurt Rose and Mahmoud Hashemi"
__contact__ = "kurt@kurtrose.com"
__license__ = 'Apache License 2.0'

setup(
    name="pocket-protector",
    description="Handy secret management system with a convenient CLI and readable storage format.",
    author=__author__,
    author_email=__contact__,
    license=__license__,
    platforms='any',
    version="0.1.0",
    long_description=__doc__,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={'console_scripts': ['pprotect = pocket_protector.cli:main']},
    install_requires=['attrs',
                      'boltons',
                      'PyNaCl',
                      'ruamel.yaml',
                      'schema']
)
