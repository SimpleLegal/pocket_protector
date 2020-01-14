# Pocket Protector 🔏

Pocket Protector provides a cryptographically-strong, serverless secret
management infrastructure. Pocket Protector enables *key management as
code*, securely storing secrets in a versionable format, right
alongside the corresponding application code.

Pocket Protector's approach lets you:

* Leverage existing user, versioning, and backup systems, with no
  infrastructure to set up
* Support multiple environments
* Integrate easily with existing key management systems
  (AWS/Heroku/TravisCI)

Pocket Protector also:

* Minimizes the number of passphrases and keys your team has to
  remember and secure
* Beats the heck out of hardcoded plaintext secrets!


## Installation

Right now the easiest way to install Pocket Protector across all
platforms is with `pip`:

```sh
pip install pocket_protector
```

This will install the command-line application `pocket_protector`,
conveniently shortened to `pprotect`, which you can use to test your
installation:

```sh
$ pprotect version
pocket_protector version 18.0.1
```

Once the above is working, we're ready to start using Pocket Protector!


## Usage

Pocket Protector aims to be as easy to use as a secret management
system can get. That said, understanding security takes time, so be
sure to go beyond the quick start and reference below, and read our
[User Guide](https://github.com/SimpleLegal/pocket_protector/blob/master/USER_GUIDE.md)
as well.


### Quick start

Pocket Protector's CLI is its primary interface. It presents a compact
set of commands, each representing one action you might want to take
on a secret store. Basic usage starts on your laptop, inside your
checked out code repository:

```sh
# create a new protected file
pprotect init

# add a key domain
pprotect add-domain

# add a secret to the new key domain
pprotect add-secret

# decrypt and read out the secret
pprotect decrypt-domain
```

Each of these will prompt the user for credentials when necessary. See
the section below on passing credentials.

When you're done updating the secret store, simply `git commit` (or
equivalent) to save your changes. Should you make any mistakes, use
your VCS to revert the changes.


### Passing credentials

By default, the `pocket_protector` command prompts you for credentials
when necessary. But convenience and automation both demand more
options, highlighted here:

* Command-line Flags
  * `-u / --user USER_EMAIL` - specifies the user email for subcommands which require it
  * `--passphrase-file PATH` - specifies a path to a readable file
    which contains the passphrase (useful for mount-based key
    management, like Docker)
  * `--domain DOMAIN` - specifies the name of the domain
  * `--non-interactive` - causes the command to fail when credentials cannot be gotten by other means

* Environment variables
  * `PPROTECT_USER` - environment variable which contains the user email
  * `PPROTECT_PASSPHRASE` - environment variable which contains the
    passphrase (useful for environment variable-based key management,
    used by AWS/Heroku/many CI systems)

In all cases, flags take precedence over environment variables, and
both take precedence over and bypass interactive prompts. In the event
an incorrect credential is passed, `pocket_protector` does *not*
automatically check other sources.


See our
[User Guide](https://github.com/SimpleLegal/pocket_protector/blob/master/USER_GUIDE.md)
for more usage tips.


### Command summary

Here is a summary of all commands:

```
usage: pprotect [COMMANDS]

Commands:
  add-domain            add a new domain to the protected
  add-key-custodian     add a new key custodian to the protected
  add-owner             add a key custodian as owner of a domain
  add-secret            add a secret to a specified domain
  decrypt-domain        decrypt and display JSON-formatted cleartext for a
                        domain
  init                  create a new pocket-protected file
  list-all-secrets      display all secrets, with a list of domains the key is
                        present in
  list-audit-log        display a chronological list of audit log entries
                        representing file activity
  list-domain-secrets   display a list of secrets under a specific domain
  list-domains          display a list of available domains
  list-user-secrets     similar to list-all-secrets, but filtered by a given
                        user
  rm-domain             remove a domain from the protected
  rm-owner              remove an owner's privileges on a specified domain
  rm-secret             remove a secret from a specified domain
  rotate-domain-keys    rotate the internal keys for a particular domain (must
                        be owner)
  set-key-custodian-passphrase
                        change a key custodian passphrase
  update-secret         update an existing secret in a specified domain
```


## Design

The theory of operation is that the `protected.yaml` file consists of
"key domains" at the root level. Each domain stores data encrypted by
a keypair. The public key of the keypair is stored in plaintext, so
that anyone may encrypt and add a new secret. The private key is
encrypted with the owner's passphrase. The owners are known as "key
custodians", and their private keys are protected by passphrases.

Secrets are broken up into domains for the purposes of granting
security differently. For example, `prod`, `dev`, and `stage` may all
be different domains. Protected stores may have as few or as many
domains as the team and application require.

To allow secrets to be accessed in a certain environment, Pocket
Protector must be invoked with a user and passphrase. As long as the
credentials are correct and the user has permissions to a domain, all
secrets within that domain are unlocked.

Passphrase security will depend on the domain. For instance, a domain
used for local development may set the passphrase as an environment
variable, or hardcode it in a configuration file.

On the other hand, a production domain would likely require manual
entry of an authorized release engineer, or use AWS/GCP/Heroku key
management solutions to inject the passphrase.

for prod domains, use AWS / heroku key management to store
the passphrase

An application / script wants to get its secrets:
```python
# at initialization
secrets = KeyFile.decrypt_domain(domain_name, Creds(name, passphrase))
# ... later to access a secret
secrets[secret_name]
```

An application / script that wants to add / overwrite a secret:
```python
KeyFile.from_file(path).with_secret(
    domain_name, secret_name, value).write()
```

Note -- the secure environment key is needed to read secrets, but not write them.
Change management on secrets is intended to follow normal source-code
management.

File structure:
```yaml
[key-domain]:
  meta:
    owners:
      [name]: [encrypted-private-key]
    public_key: [b64-bytes]
    private_key: [b64-bytes]
  secret-[name]: [b64-bytes]
key-custodians:
  [name]:
    public-key: [b64-bytes]
    encrypted-private-key: [b64-bytes]
```


### Threat model

An attacker is presumed to be able to read but not write the contents
of `protected.yaml`. This could happen because a developer's laptop
is compromised, GitHub credentials are compromised, or (most likely)
Git history is accidentally pushed to a publicly acessible repo.

With read access, an attacker gets environment and secret names,
and which secrets are used in which environments.

Neither the file as a whole nor individual entries are signed,
since the security model assumes an attacker does not have
write access.


### Notes

Pocket Protector is a streamlined, people-centric secret management
system, custom built to work with distributed version control systems.

* Pocket Protector is a data protection tool, not a change management
  tool. While it has convenient affordances like an informal
  `audit_log`, Pocket Protector is meant to be used in conjunction with
  your version management tool. Signed commits are a particularly good
  complement.
* Pocket Protector is designed for single-user usage. This is not a
  scaling limitation as much as it is a scaling feature. Single-user
  means that every `pprotect` command needs at most one credentialed
  user present. No sideband communication is required, minimizing
  leakage, while maintaining a system as distributed as your version
  management.


## FAQ


### Securing Write Access

Pocket Protector does not provide any security against unauthorized writes
to the `protected.yaml` file, by design. Firstly, without any Public Key Infrastructure,
Pocket Protector is not a good basis for cryptographic signatures. (An attacker
that modifies the file could also replace the signing keypair with their own;
the only way to detect this would be to have a data-store outside of the file.)

Secondly -- and more importantly -- the Git or Mercurial repository already has
good controls around write access. All changes are auditable, authenticated with
ssh keypairs or user passphrases. For futher security, consider using signed commits:

* https://git-scm.com/book/id/v2/Git-Tools-Signing-Your-Work
* https://help.github.com/articles/signing-commits-using-gpg/
* https://docs.gitlab.com/ee/user/project/repository/gpg_signed_commits/index.html
