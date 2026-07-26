# go-cgp-acme

An ACME (Let's Encrypt) client for the
[CommuniGate Pro](https://communigatepro.ru/) server: renews the
TLS certificates of CGP domains and their aliases, serving http-01
challenges out of each domain's unnamed Skin and installing issued
certificates via the PWD/CLI protocol
([go-cgp-api](https://github.com/gmyzovsky/go-cgp-api) +
[go-cgp-data](https://github.com/gmyzovsky/go-cgp-data)).

This client is designed for deployments where a wildcard certificate
is not an option - e.g. SIP services, where RFC 5922 forbids any form
of wildcard in certificates - and every domain plus its aliases needs
its own certificate.

The full cycle works and has been verified against a live 4-node CGP
6.5 Dynamic Cluster, on both the Let's Encrypt staging and production
environments: renewal decisions (certificate expiry, missing aliases,
and PKI Services checks), the local challenge rehearsal described
below, http-01 validation through Skin files, issuance, archiving of
the previous key/certificates into File Storage as PEM, and
installation.

## Configuration

All site configuration lives in a TOML file; see
[go-cgp-acme.example.toml](go-cgp-acme.example.toml). Without `-config`,
the client looks for `go-cgp-acme.toml` next to the executable (so a
portable copy travels with its config) and then `/etc/go-cgp-acme.toml`
(where a `.deb`/`.rpm` package installs it). Command-line flags
(`--onlylocal`, `--onlyshared`, `--staging`, `--domain`, `--exclude`,
`--force`, `--verbose`) override it per run.

The packaged configuration is installed `root:mail`, mode `0660`, the
same ownership CommuniGate Pro gives its own files. A typical Server
Administrator is in group `mail` already, so it is editable without
`sudo` and readable by nobody else. Package upgrades leave it alone.

### One-off runs

For a one-time issue or renewal no configuration file is needed. When
`-config` is not given and the default `/etc/go-cgp-acme.toml` is
absent, the client runs standalone against Let's Encrypt (production,
or staging under `--staging`) and asks for the CGP connection
interactively. The connection may instead be given on the command line
as `login:password@host:port`:

```sh
go-cgp-acme --domain sip.example.org 'postmaster@example.org:secret@mail.example.org'
```

The port defaults to 106, and an omitted password is prompted for
without echo. The host is taken after the last `@`. A login given
without a domain part is qualified with that host (`login@host`) so it
authenticates in the domain you connect to, rather than one CommuniGate
Pro infers from the connection's IP binding; to send a specific
`login@domain` regardless of host, spell it out (`login@domain@host`).
A connection string overrides the `[cgp]` section even when a
configuration file is loaded, letting one file drive several servers;
other CAs and External Account Binding still require a configuration
file.

## Challenge rehearsal

Every domain about to be renewed is rehearsed locally first: for each
name the certificate is to cover, the client stores a random token as a
Skin file, fetches it back over plain HTTP from that public name, and
removes it again. No CA is involved, so a name that cannot answer costs
no ACME request and no failed order.

The case this is built for is a domain alias that is not in DNS, or
points somewhere else entirely. Its absence from the certificate is
itself a reason to renew, so without the rehearsal every run would
order a certificate and every order would fail on that name. Instead
the alias is excluded for the rest of the run and the domain is
re-checked - and when the missing alias was the only reason to renew,
nothing is ordered at all:

```
MAIN [ example.org ] needs certificate (alias www.example.org not in certificate), SANs [example.org www.example.org]
SELF [ www.example.org ] http-01 DNS: name does not resolve
SELF [ example.org ] alias www.example.org cannot answer http-01 (DNS: name does not resolve); excluded for this run
SELF [ example.org ] add "www.example.org" to domains.exclude to stop reconsidering it
MAIN [ example.org ] no renewal needed after exclusion: valid until 2026-10-24
```

Add such a name to `domains.exclude` (or `--exclude`) to settle it
permanently. A domain that cannot answer for its *own* name is skipped
and counted as a failed renewal - a certificate without it is
pointless.

`--self-test` answers both halves of the question - what a run would do
and whether it could - without renewing anything. It prints the same
renewal decisions a real run prints, rehearses every selected domain
(not only the ones due for renewal: a name that cannot answer is worth
knowing about before its certificate is about to expire), and ends with
a table:

```
MAIN [ example.org ] needs certificate (alias www.example.org not in certificate), SANs [example.org www.example.org]
SELF [ example.org ] alias www.example.org cannot answer http-01 (DNS: name does not resolve); excluded for this run
SELF [ example.org ] add "www.example.org" to domains.exclude to stop reconsidering it
MAIN [ example.org ] no renewal needed after exclusion: valid until 2026-10-24

NAME                              HTTP-01  COMMENT
--------------------------------------------------
example.org                       PASS
-> www.example.org                DNS      name does not resolve
-> mail.example.org               404      challenge not served, try --HTTPServeAcmeChallenge YES

MAIN self-test: 0 domain(s) would be renewed
```

It exits non-zero when any name fails. Nothing is ordered, archived or
installed, so this is also the way to see what a run would change
before letting it run.

`--staging` goes one step further and exercises the CA as well: it
orders from the staging endpoint, reports the certificate it got (with
`--verbose`, prints the chain in PEM), and stops there. Domain settings
are never touched, since a test CA's certificate would only spoil them
and writing settings is not the part of the cycle worth rehearsing.
Because there is no certificate to protect, staging implies `--force`:
it orders for every selected domain rather than only for those due,
which is the whole point of asking. Nothing on the server changes, so a
staging run never settles - it will order again the next time it runs.

Output level is `verbose` in the file (0, 1, or 2) and `--verbose` on
the command line, repeated to raise it; the command line replaces the
file's level outright, so `-verbose=false` quiets a chatty
configuration for one run. There is no `staging` in the file on
purpose: a run that reports its certificate instead of installing it is
worth asking for while testing, not a state to leave a machine in.

At level 2 the ACME exchange itself is traced - every request and
response, with the JWS payload decoded and the JSON printed:

```
ACME > POST https://acme-v02.api.letsencrypt.org/acme/new-order
ACME >   {"identifiers":[{"type":"dns","value":"example.org"}]}
ACME < 201 Created (193ms)
ACME <   Location: https://acme-v02.api.letsencrypt.org/acme/order/1/2
ACME <   { "status": "pending", "expires": "2026-08-02T07:00:49Z", ... }
```

The certificate chain is summarized rather than dumped, and the account
key never appears. This is the level to run at when a CA rejects
something and its own words are the answer.

## Archive

Before a domain's key and certificate are replaced, the ones in place
are copied into File Storage, one file per field of the domain's
Security page in WebAdmin:

```
<storage.path>/archive/<domain>/<timestamp>-privkey.pem
<storage.path>/archive/<domain>/<timestamp>-cert.pem
<storage.path>/archive/<domain>/<timestamp>-chain.pem
```

## Cluster operation

In a CGP Dynamic Cluster the tool runs on every node: each node with
`--onlylocal` renews its local domains (its guaranteed-local main
domain plus any regular non-Shared domains), and one designated node
runs with `--onlyshared` to renew the Shared (cluster-wide) domains.
Passing both cancels out - both are ignored.

## Requirements

- CommuniGate Pro 6.1.9+ (http-01 challenges are served by CGP itself,
  started with `--HTTPServeAcmeChallenge YES`)
- A Server Administrator CLI account with one access right, `Can
  Modify All Domains and Accounts Settings` - see below. Since a Server
  Administrator lives in the node's main domain, its File Storage -
  where the ACME account key and the certificate archive are kept - is
  node-local: in a cluster, each node maintains its own ACME account
  and archive.
- Certificates are RSA (CommuniGate Pro does not support ECDSA; keys
  are installed as PKCS#1)

## Access rights

The account this tool authenticates as needs exactly **one** Server
access right: `Can Modify All Domains and Accounts Settings`. Not
`Master`, and nothing from the Settings, Monitors or Directory realms.
Granting it more is granting it more than it can use.

That one right is enough because CommuniGate Pro counts it as the read
right wherever a read right is asked for, and because an account
holding it passes the per-setting filter on domain updates unrestricted.
What the tool sends, and what each command is checked against:

| Command | Right required |
| --- | --- |
| `GETVERSION` | none |
| `GETACCOUNTPREFS *` | none - reading one's own Account is self-access |
| `READSTORAGEFILE`, `WRITESTORAGEFILE` | none - the tool only ever uses its own File Storage |
| `LISTDOMAINS`, `LISTCONTROLLEDDOMAINS` | `Can Read All Domains and Accounts Settings` |
| `GETDOMAINALIASES`, `GETDOMAINSETTINGS`, `GETDOMAINEFFECTIVESETTINGS`, `LISTDOMAINSKINS` | read access to the domain |
| `UPDATEDOMAINSETTINGS` (the key, certificate and CA chain) | write access to the domain |
| `CREATEDOMAINSKIN`, `STOREDOMAINSKINFILE` (and its `DELETE` form) | `CanModifySkins` on the domain |

### Without a Server Administrator

A Domain Administrator can run it for their own domains, with two
Domain Administration rights: `CanModifySkins`, for the challenge
files, and `CertificateType`, which is what lets an update carry the
private key, certificate and CA chain. Two conditions, both about
avoiding the two commands in the table that need a server-wide right:

- name the domains, with `domains.include` or `--domain`, so nothing
  calls `LISTDOMAINS`
- do not use `--onlylocal` or `--onlyshared`, which are cluster-wide
  questions by definition

The ACME contact then comes from the account's own address, and the
account key and archive live in that account's File Storage.

## Development

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

Sibling modules `go-cgp-api`/`go-cgp-data` are used via an uncommitted
`go.work` during development; released versions are required in
`go.mod`.
