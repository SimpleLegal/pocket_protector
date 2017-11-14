# PocketProtector User Guide

PocketProtector is a streamlined, human-centric secret management
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
pocket_protector version 17.0.0
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
Adding new domain.
User email: tom@example.com
Passphrase:
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

One of PocketProtector's biggest features is its distributed
design. Any action performed with PocketProtector only requires one
set of credentials, if it requires credentials at all. This enables
teams, local and remote, to securely share keys without requiring side
channels. We'll see more of this in the sections ahead.

<!--

* link key custodian
* link "yaml"
* talk about blame

-->
## FAQ
