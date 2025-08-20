# tlspeek

## Description

`tlspeek` is a command-line tool for inspecting the TLS certificate of a server.

Its main feature is the ability to display certificate information even if a full TLS/SSL handshake cannot be completed. This is particularly useful in scenarios where the server requires a client certificate for authentication, which would normally prevent tools like `openssl s_client` from easily retrieving the server certificate.

`tlspeek` works by initiating a TLS connection and extracting the server's certificate from the initial part of the handshake, without requiring the handshake to succeed.

The tool supports connecting via HTTP/HTTPS and SOCKS5 proxies.

## Building

To build the tool, you need to have Go installed.

```bash
go build tlspeek.go
```

This will create an executable file named `tlspeek` in the current directory.

## Usage

```
Usage:
  ./tlspeek --ip <IP> --port <port> [--sni <hostname>] [--proxy <url>] [--timeout 7s] [--dump-pem]

Proxy examples: http://user:pass@proxy:8080  |  socks5://user:pass@proxy:1080
```

### Options

| Flag          | Description                                                                                                                              | Default |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `--ip`        | **(Required)** The IP address of the target server.                                                                                      |         |
| `--port`      | The port of the target server.                                                                                                           | `443`   |
| `--sni`       | The hostname to use for Server Name Indication (SNI). This is crucial for servers hosting multiple sites on a single IP.                  |         |
| `--proxy`     | A URL for an HTTP/HTTPS or SOCKS5 proxy. Also reads from `HTTPS_PROXY` / `HTTP_PROXY` environment variables if not specified.              |         |
| `--timeout`   | Connection timeout. Accepts values like `5s`, `1m`, etc.                                                                                 | `7s`    |
| `--dump-pem`  | If specified, dumps the entire server certificate chain to standard output in PEM format.                                                |         |
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
NotBefore  : 2024-05-15T00:00:00Z
NotAfter   : 2025-05-14T23:59:59Z
Thumbprint : 2435D395563712613C25964528651662747B2562
SANs       : github.com www.github.com
```

### Using SNI

If the server hosts multiple TLS-enabled sites, you must specify the hostname using the `--sni` flag to get the correct certificate.

```bash
# Get the certificate for cloudflare.com from one of its IPs
./tlspeek --ip 104.16.132.229 --sni cloudflare.com
```

### Dumping the Certificate Chain

Use the `--dump-pem` flag to get the full certificate chain in PEM format, which can be piped to other tools like `openssl`.

```bash
./tlspeek --ip 140.82.121.4 --sni github.com --dump-pem
```
Output:
```
Subject    : C=US,ST=California,L=San Francisco,O=GitHub, Inc.,CN=github.com
Issuer     : C=US,O=DigiCert Inc,CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1
CN         : github.com
NotBefore  : 2024-05-15T00:00:00Z
NotAfter   : 2025-05-14T23:59:59Z
Thumbprint : 2435D395563712613C25964528651662747B2562
SANs       : github.com www.github.com

--- BEGIN CERTIFICATE CHAIN ---
-----BEGIN CERTIFICATE-----
MIIJ5jCCCM6gAwIBAgIQDBh5s4V2EmE8JZZEKGV2YnANBgkqhkiG9w0BAQsFADBh
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIQaN24d2s4J24A99S3M1I+mjANBgkqhkiG9w0BAQsFADBh
...
-----END CERTIFICATE-----
--- END CERTIFICATE CHAIN ---
```

### Using a Proxy

Connect through an HTTP or SOCKS5 proxy.

```bash
# Via an HTTP proxy
./tlspeek --ip 140.82.121.4 --sni github.com --proxy http://proxy.example.com:8080

# Via an authenticated SOCKS5 proxy
./tlspeek --ip 140.82.121.4 --sni github.com --proxy socks5://user:password@socks.example.com:1080
```
