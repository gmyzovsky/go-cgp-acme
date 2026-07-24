# go-cgp-acme

An ACME (Let's Encrypt) client for the
[CommuniGate Pro](https://www.communigatepro.com/) server: renews the
TLS certificates of CGP domains and their aliases, serving http-01
challenges out of each domain's unnamed Skin and installing issued
certificates via the PWD/CLI protocol
([go-cgp-api](https://github.com/gmyzovsky/go-cgp-api) +
[go-cgp-data](https://github.com/gmyzovsky/go-cgp-data)).

The Go successor of `le-cgatepro.pl`, built for deployments where a
wildcard certificate is not an option - e.g. SIP services, where RFC
5922 forbids any form of wildcard in certificates - and every domain
plus its aliases needs its own certificate.

> **Status: under construction.** Domain enumeration and renewal
> decisions (certificate expiry, missing aliases, issuer and PKI
> Services checks) work read-only; ACME issuance and installation are
> being ported. `--dry-run` is the only mode that should be pointed at
> a production server today.

## Configuration

All site configuration lives in a TOML file (default
`/etc/go-cgp-acme.toml`); see
[go-cgp-acme.example.toml](go-cgp-acme.example.toml). Command-line
flags (`--mainonly`, `--staging`, `--domain`, `--exclude`, `--force`,
`--dry-run`, `--verbose`) override it per run.

## Cluster operation

In a CGP Dynamic Cluster the tool runs on every node: each node with
`--mainonly` renews its guaranteed-local main domain, except one
designated node that runs without it and handles the shared
(cluster-wide) domains as well.

## Requirements

- CommuniGate Pro 6.1.9+ (http-01 challenges are served by CGP itself,
  started with `--HTTPServeAcmeChallenge YES`)
- A CLI account with Domain Administration rights
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
