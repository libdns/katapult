# Katapult for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/katapult)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Katapult](https://katapult.io), allowing you to manage DNS records.

## Authentication

To use this package you will need a Katapult API token, see the [Katapult docs](https://docs.katapult.io/docs/dev/key-concepts/authentication) for more information.

## Example

See the `example/main.go` file for a demonstration on how to use the package. The example can be ran by specifying the API token and zone:

```
LIBDNS_KATAPULT_API_TOKEN=your-api-token LIBDNS_KATAPULT_ZONE=your-domain go run ./example
```

The example can be modified to try different functions available on the provider.

## Tests

The unit tests run against an in-memory fake of the Katapult API, so need no credentials:

```
go test ./...
```

There are also integration tests which use the real Katapult API. These create and remove records under `libdns-test` in the zone, so you should use a test domain/zone:

```
LIBDNS_KATAPULT_API_TOKEN=your-api-token LIBDNS_KATAPULT_ZONE=your-domain go test -tags integration -run Integration -v
```

API tokens restricted to ACME challenges can only manage `_acme-challenge` TXT records; tests for other record types are skipped when using one.
