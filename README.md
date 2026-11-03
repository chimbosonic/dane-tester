# DANE Tester

DANE tester is available in two variants:

- `dane-tester` a CLI tool
- `dane-tester-server` an API and Frontend

Both use the same library for testing and debugging [OpenPGP DANE (RFC 7929)](https://datatracker.ietf.org/doc/rfc7929/) OPENPGPKEY DNS records.

You can find `dane-tester-server` hosted by `Alexis Lowe <alexis.lowe@chimbosonic.com>` at https://dane.dp42.dev

## CLI: Install

Clone this repo and go to the folder then run:

```bash
$ cargo install --path cli
```

## CLI: Usage

```bash
$ dane-tester --help
A CLI tool for testing and debugging OpenPGP DANE (RFC 7929) OPENPGPKEY DNS records

Usage: dane-tester --user-id <USER_ID>

Options:
  -u, --user-id <USER_ID>  The GPG User ID to look up (example: Joe.Doe@example.org)
  -h, --help               Print help
  -V, --version            Print version
```

## Environment Variables

### `DNS_SERVER`

By default lookups are fully recursive: they start at the root servers and validate DNSSEC from the root trust anchor. This needs outbound UDP and TCP port 53 to any authoritative name server.

The root server addresses come from IANA's root hints file, vendored at `dane/named.root` and embedded at build time. Refresh it with `make update-root-hints`.

Optionally set `DNS_SERVER` to an IP address to forward lookups to that resolver instead. DNSSEC is still validated locally.

```bash
$ DNS_SERVER=1.1.1.1 dane-tester -u user@example.com
```

Port 53 is assumed.

This works for both the CLI and the server.

## Server: Usage

Clone the repo, make sure to update `server/src/config.rs`

### CAUTION

- `root_path` does **not** change server routing. It only affects paths referenced in generated/static content.
- `root_path` must **not** end with `/`.
  - Use `""` for the site root.
  - If you proxy the server under a subpath (e.g. `https://example.org/dane`), set `root_path` to `/dane`.

**Swagger UI note:** If `root_path != ""`, the Swagger UI page will break because it hardcodes `/api-docs/openapi.json`. I wasn't able to get `utoipa` to change the path used in the frontend.


and then build the server container:
```bash
docker build -t dane-tester .
```

Then run it with:
```bash
docker run -it --rm -p 7070:7070 dane-tester
```

To forward lookups to a DNS server instead of resolving recursively:
```bash
docker run -it --rm -p 7070:7070 -e DNS_SERVER=1.1.1.1 dane-tester
```

## Tracing
To enable tracing for the `dane` library run the server with the following:
```bash
cd server/
export RUST_LOG="info,dane=trace"; cargo watch -x run --features otel
```
and in another terminal:
```bash
docker run  -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one:latest
```
