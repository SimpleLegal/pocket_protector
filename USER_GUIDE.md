# PocketProtector User Guide

PocketProtector is a streamlined, people-centric secret management
system, built to work with modern distributed version control systems.

This guide will walk you through security scenarios commonly faced by
teams, and showcase how PocketProtector's no-nonsense workflow offers
a practical alternative to more complicated solutions.

## Starting out

Let's say we have a small engineering team building a software service
whose source code is versioned in git, and they're looking to improve
their secret management. Our team consists of Engineer Alice, Engineer
Bob, CEO Claire, and CTO Tom.

The service interacts with other services, including an email
service. The email service provides an API key, which Claire checked
into the code on day 1, despite Tom's protests.

Let's migrate to a better way, the PocketProtector way!

## Installation

Right now, the easiest way to install PocketProtector across all
platforms is with `pip`:

```
pip install pocket_protector
```

This will install a command-line application, `pocket_protector`,
conveniently shortened to `pprotect`, which you can use to test your
installation:

```
$ pprotect version
pocket_protector version 20.0.0
```

Once the above is working, we're ready to start using PocketProtector!

## Creating a New Protected

With PocketProtector, secrets are encrypted and stored in a file which
is versioned alongside your code. Create this file like so:

```
$ pprotect init
```

You'll be prompted to add a *key custodian*, an administrator for the
secrets we're trying to protect. In our scenario, CTO Tom would be the
natural choice for our first key custodian.

```
tom@tomtop $ pprotect init
Adding new key custodian.
User email: tom@example.com
Passphrase:
Retype passphrase:
```

After successfully creating his credentials, Tom would see a
`protected.yaml` now exists in his current directory:

```
tom@tomtop $ ls -l protected.yaml
-rw-rw-r-- 1 tom tom 275 Nov 13 16:25 protected.yaml
```

PocketProtector will store all secrets encrypted in this YAML file,
which is always safe to check in to the project's repository. It's
commonly put at the root of the repository for discoverability, but
the protected.yaml is self-contained and can exist anywhere in the
project tree.

## Adding a Domain

Right now, the protected only contains credentials for our sole key
custodian, CTO Tom. Before anyone can add any secrets, Tom needs to
create one or more *domains*.

A domain can represent any set of keys accessible to the same actors,
and in our scenario we're going to have one domain per environment,
which means one domain for `prod` (our production datacenter) and one
for `local` (our development laptops).

```
tom@tomtop $ pprotect add-domain
User email: tom@example.com
Passphrase:
Adding new domain.
Domain name: dev
```

Tom verifies his credentials and creates the "dev" domain, then does
the same for the "prod" domain.

> **Tip**: Almost all `pprotect` subcommands accept a `--confirm-diff`
> option, which enables you to see the actual changes being made to the
> protected file, with a prompt to accept or reject. You can use this
> functionality to do dry runs of changes, and don't forget that you can
> and should commit the file regularly so you can revert any changes you
> don't want.

Now that we have our first custodian and our two domains, we're ready
to start adding secrets!

## Adding Secrets

So far CTO Tom has done all the work. Now it's time for our Engineers
to pick up the slack. CTO Tom asks Engineer Alice to start
investigating chat integration. Since the chat service requires an API key, Alice is
going to have a secret on her hands.

Alice installs `pprotect`, pulls the repo with `protected.yaml`
created by Tom. She adds the "chat-api-key" to the protected's `dev`
domain like so:

```
alice@alicetop $ pprotect add-secret
Adding secret value.
Domain name: dev
Secret name: chat-api-key
Secret value: abc5ca1ab1e
```

Notice that PocketProtector did not prompt Alice for any
credentials. Because they were added to the "dev" domain, they were
safely added by encrypting them with a key accessible only to Tom
right now.

But how did the secret get secured without requiring an authenticated
user?

### PocketProtector Secret Storage by Analogy

The best analogy for PocketProtector's internal domain security
mechanism comes from [the NaCl project](#), on top of which PocketProtector
is implemented.

Imagine you're a security-conscious community member, holding a letter
you'd like a select few of your neighbors to read.

You want them to securely read the notarized original, so they can be
as sure of the authenticity as you are. A copy simply won't
do. Because we can't make copies of the letter, how do we securely
ensure only specific neighbors read it?

One elegant solution is to put the letter in your own mailbox, and
make copies of your mailbox key. Then, put a copy of the key (with
instructions) into each of the neighbors' mailboxes.

PocketProtector uses a cryptographic approach known as two-key
encryption to implement this scheme. Every domain is a mailbox, and
only key custodians assigned to that domain are neighbors with a key
to that mailbox.

Another advantage of PocketProtector's scheme is that you don't have
to own the mailbox to put another letter in, just as we saw with our
[Adding Secrets](#adding-secrets) scenario, above. Domains are
community mailboxes, where only specific community members have access
to the contents.

Thus, PocketProtector provides read protection against leaks,
unintentional or otherwise, while relying on repository management
practices for write protection. Anyone with push rights to the repo
can add a key. In our analogy, only people in the building can drop
letters in the mailbox, but it's up to your team to control who can
get into the building (i.e., push to your repo).

Speaking of reads, let's check in on our scenario using some
PocketProtector's read subcommands.

## Reading a Protected

The first thing to recognize about protected files is that they are
designed for some degree of human readability. They are plaintext YAML
files that you can open in your editor of choice. You should see
something like this:

```
dev:
  secret-chat-api-key: ABpVkJKq6WgOgl0rQYDSB0zAjNGD1Gn4aEFmWthMd9l+hjz8rjBJYDm/guyeIVZOwj7m/TQPJNz/yw0D
  meta:
    public-key: AKKRHVwQcbLkk2yK7L3DWmTKzqYhlFuavNpdzl//hbk1
    owners:
      tom@example.com: ANrCtPEyppOZt7waOrW/GDQTd7+/tGTLJNqmtaxX8FhbYVsbPWVgSdvzVNEUVM3/bRFsfpw5GHmF93qVwqC7wUtNnIngp1qiDpGyN12iVHEZ
key-custodians:
  tom@example.com:
    pwdkm: ALLq2pN0MCqlQ3V0SAl7d71zeOd1D0vBzjZ6y5L5uK3TFMuDKe5uCAA=
audit-log:
- 2020-01-22T18:06:40Z -- created key custodian tom@example.com
- 2020-01-22T19:46:15Z -- created domain dev with owner tom@example.com
- 2020-01-22T19:46:38Z -- added secret chat-api-key in dev
```

All of the state PocketProtector needs to operate is included in this
file. Several of the text values should be recognizable from our
scenario above.

But there are more convenient ways to get access to the values
designed for external consumption. Let's take a look, with a file
that's had a couple more values added to it.

### Listing available domains

The first way to get acquainted with a protected is to list the
domains within the file.

```
$ pprotect list-domains
dev
prod
```

As we can see, Tom has added a `prod` domain in addition to the `dev`
one we created above. Many projects need to function in multiple
environments, and PocketProtector's domains are a natural way to
segment the different secrets used in each environment.

### Listing secrets within a given domain

If we know which domain we want to inspect, we can list its secrets
like so:

```
$ pprotect list-domain-secrets dev
chat-api-key
mail-api-key
```

It seems Tom has recently added a new key for mail integration, in
addition to the chat key we added above.

But just because a key is in one domain, doesn't mean it has to be in
all of them. Let's get an overview.

### Listing all secrets in a protected

Because domains can overlap and also diverge, it can be very useful to
get an overview of all the secrets contained in a protected. The
`list-all-secrets` subcommand gives a sorted list with each secret,
followed by a colon and a comma-separated list of domains that contain
that secret, like so:

```
$ pprotect list-all-secrets
chat-api-key: dev
mail-api-key: dev, prod
```

As we can see, that mail integration key is actually present for both
`dev` and `prod` domains, so Tom may have rush deployed that
integration already.

The actual values for these secrets may or may not be the same. In
practice none of them should be, but even if they were, inspecting the
file would not give any indication, because internally different
encryption keys are used for each domain.

### Listing activity on the protected file

So far we've focused on protected domains and secrets, but
PocketProtector also builds in one very useful metadata feature: The
audit log.

The audit log keeps a human readable list of operations performed on
the protected. You can see this in our full-text example above, but
you can also access it from the command line, one entry per line:

```
$ pprotect list-audit-log
created key custodian tom@example.com
created domain dev with owner tom@example.com
added secret chat-api-key in dev
created domain prod with owner tom@example.com
added secret mail-api-key in dev
added secret mail-api-key in prod
```

And here we can see how it all went down. It's far from complete, but
it's a pretty good summary that should be used in conjunction with
your source control management tools. Using `git` as an example, `git
log protected.yaml` and `git blame protected.yaml` are both excellent
complements to the audit log.

The audit log is also completely supplementary. It can safely be
truncated without affecting any other PocketProtector functionality.

<!--
## TODO

One of PocketProtector's biggest features is its distributed
design. Any action performed with PocketProtector only requires one
set of credentials, if it requires credentials at all. This enables
teams, local and remote, to securely share keys without requiring side
channels. We'll see more of this in the sections ahead.



* link key custodian
* link "yaml"
* talk about blame

Steps:

* Starting
* Add manager
* Add domain (environment)
    * Creator becomes first owner
* Add a secret
* Grant access to domain
* Update your passphrase
* Removing a custodian (i.e., what to do when someone leaves)
* Updating or removing secrets
* Rotations


-->
