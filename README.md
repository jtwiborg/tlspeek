# tlspeek

## Description

`tlspeek` is a command-line tool for inspecting the TLS certificate of a server.

Its main feature is the ability to display certificate information even if a full TLS/SSL handshake cannot be completed. This is particularly useful in scenarios where the server requires a client certificate for authentication, which would normally prevent tools like `openssl s_client` from easily retrieving the server certificate.

`tlspeek` works by initiating a TLS connection and extracting the server's certificate from the initial part of the handshake, without requiring the handshake to succeed.

The tool supports connecting via HTTP/HTTPS and SOCKS5 proxies.

## Pre-built Binaries

Pre-built binaries for all supported platforms are available in the `dist/` directory:

| Platform       | File                            |
|----------------|---------------------------------|
| macOS ARM64    | `dist/tlspeek-darwin-arm64`     |
| macOS AMD64    | `dist/tlspeek-darwin-amd64`     |
| Linux ARM64    | `dist/tlspeek-linux-arm64`      |
| Linux AMD64    | `dist/tlspeek-linux-amd64`      |
| Windows ARM64  | `dist/tlspeek-windows-arm64.exe`|
| Windows AMD64  | `dist/tlspeek-windows-amd64.exe`|

### Verifying Checksums

SHA256 checksums are provided in `dist/sha256sums.txt`. To verify:

```bash
cd dist && shasum -a 256 -c sha256sums.txt
```

## Building from Source

### Prerequisites

- [Go](https://golang.org/) 1.21 or later

### Quick Build (current platform)

```bash
go build -o tlspeek tlspeek.go
```

### Cross-compile All Platforms

```bash
make build VERSION=1.2.0
```

### Build with Checksums

```bash
make all VERSION=1.2.0
```

### Clean

```bash
make clean
```

The `VERSION` parameter is optional — if omitted, it defaults to the latest git tag or `dev`.

## Usage

```
Usage:
  ./tlspeek --host <host|IP> [--port <port>] [--sni <hostname>] [--proxy <url>] [--timeout 7s] [--dump-pem] [--json]
  --ip is an alias for --host

Proxy examples: http://user:pass@proxy:8080  |  socks5://user:pass@proxy:1080
```

### Options

| Flag          | Description                                                                                                                              | Default |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `--host`      | **(Required)** The hostname or IP address of the target server.                                                                          |         |
| `--ip`        | Alias for `--host`.                                                                                                                      |         |
| `--port`      | The port of the target server.                                                                                                           | `443`   |
| `--sni`       | The hostname to use for Server Name Indication (SNI). This is crucial for servers hosting multiple sites on a single IP.                  |         |
| `--proxy`     | A URL for an HTTP/HTTPS or SOCKS5 proxy. Also reads from `HTTPS_PROXY` / `HTTP_PROXY` environment variables if not specified.            |         |
| `--timeout`   | Connection timeout. Accepts values like `5s`, `1m`, etc.                                                                                 | `7s`    |
| `--dump-pem`  | If specified, dumps the entire server certificate chain to standard output in PEM format.                                                |         |
| `--json`      | Output all certificate information as JSON. Useful for scripting and automation.                                                          |         |
| `--version`   | Print version and exit.                                                                                                                  |         |
| `-h`, `--help`| Displays the usage information.                                                                                                          |         |


## Examples

### Basic Usage

Connect to a server by IP address to retrieve its certificate information.

```bash
./tlspeek --ip 140.82.121.4
```
Output:
```
Subject    : C=US,ST=California,L=San Francisco,O=GitHub, Inc.,CN=github.com
Issuer     : C=US,O=DigiCert Inc,CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
CN         : github.com
Serial     : 7AE2B57CF904B34E71A09F1D2A5583D9
NotBefore  : 2024-05-15T00:00:00Z
NotAfter   : 2025-05-14T23:59:59Z
Thumbprint : 2435D395563712613C25964528651662747B2562
TLSVersion : TLS 1.3
KeyType    : ECDSA P-256
SANs       : github.com www.github.com
```

### Using SNI

If the server hosts multiple TLS-enabled sites, you must specify the hostname using the `--sni` flag to get the correct certificate.

```bash
# Get the certificate for cloudflare.com from one of its IPs
./tlspeek --ip 104.16.132.229 --sni cloudflare.com
```

### JSON Output

Use `--json` for machine-readable output, e.g. with `jq`:

```bash
./tlspeek --host 140.82.121.4 --json | jq .notAfter
```

### Dumping the Certificate Chain

Use the `--dump-pem` flag to get the full certificate chain in PEM format, which can be piped to other tools like `openssl`.

```bash
./tlspeek --host 140.82.121.4 --sni github.com --dump-pem
```

### Using a Proxy

Connect through an HTTP or SOCKS5 proxy.

```bash
# Via an HTTP proxy
./tlspeek --host 140.82.121.4 --sni github.com --proxy http://proxy.example.com:8080

# Via an authenticated SOCKS5 proxy
./tlspeek --host 140.82.121.4 --sni github.com --proxy socks5://user:password@socks.example.com:1080
```
