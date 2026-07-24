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
issuer - including the staging-issuer trap, see below - and PKI
Services checks), http-01 validation through Skin files, issuance,
archiving of the previous key/certificates into File Storage
(`<path>/archive/`), and installation. Not implemented yet:
`--self-test`.

## Configuration

All site configuration lives in a TOML file (default
`/etc/go-cgp-acme.toml`); see
[go-cgp-acme.example.toml](go-cgp-acme.example.toml). Command-line
flags (`--onlylocal`, `--onlyshared`, `--staging`, `--domain`,
`--exclude`, `--force`, `--dry-run`, `--verbose`) override it per run.

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
