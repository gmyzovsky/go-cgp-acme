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
and PKI Services checks), http-01 validation through Skin files,
issuance, archiving of the previous key/certificates into File Storage
(`<path>/archive/`), and installation. Not implemented yet:
`--self-test`.

## Configuration

All site configuration lives in a TOML file (default
`/etc/go-cgp-acme.toml`); see
[go-cgp-acme.example.toml](go-cgp-acme.example.toml). Command-line
flags (`--onlylocal`, `--onlyshared`, `--staging`, `--domain`,
`--exclude`, `--force`, `--dry-run`, `--verbose`) override it per run.

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

## Cluster operation

In a CGP Dynamic Cluster the tool runs on every node: each node with
`--onlylocal` renews its local domains (its guaranteed-local main
domain plus any regular non-Shared domains), and one designated node
runs with `--onlyshared` to renew the Shared (cluster-wide) domains.
Passing both cancels out - both are ignored.

## Requirements

- CommuniGate Pro 6.1.9+ (http-01 challenges are served by CGP itself,
  started with `--HTTPServeAcmeChallenge YES`)
- A Server Administrator CLI account: it can manage every domain
  cluster-wide. Since a Server Administrator lives in the node's main
  domain, its File Storage - where the ACME account key and the
  certificate archive are kept - is node-local: in a cluster, each
  node maintains its own ACME account and archive.
- Certificates are RSA (CommuniGate Pro does not support ECDSA; keys
  are installed as PKCS#1)

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
