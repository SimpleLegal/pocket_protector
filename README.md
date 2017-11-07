The theory of operation is that the protected.yaml file
consists of key-domains at the root level.  Each key-domain
stores data encrypted by a keypair.  The public key of the
keypair is stored in plaintext, so that anyone may encrypt
and add a new secret.  The private key is stored encrypted
by an owners public key.  The owners are known as
"key custodians", their private keys are protected by passphrases.

Secrets are broken up into domains for the purposes of
granting security differently.  For example, prod, dev, and
stage may all be different domains.  The domains may
further be split up based on application specific.

Alternatively, for a simple use case everything may
be thrown into one big domain.

To allow secrets to be accessed in a certain environment,
the passphrase for an environment-specific key custodian
should be provided.

e.g. for dev domains, just hardcode the passphrase
in settings.py or similar

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

Threat model
------------
An attacker is presumed to be able to read but not write the contents
of protected.yaml.  This could happen because a developrs laptop
is compromised, github credentials are compromised, or (most likely)
git history is accidentally pushed to a publically acessible repo.

With read access, an attacker gets environment and secret names,
and which secrets are used in which environments.

Neither the file as a whole nore individual entries are signed,
since the security model assumes an attacker does not have
write access.