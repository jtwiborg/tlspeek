// tlspeek.go
package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n  %s --ip <IP> --port <port> [--sni <hostname>] [--proxy <url>] [--timeout 7s] [--dump-pem]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Proxy examples: http://user:pass@proxy:8080  |  socks5://user:pass@proxy:1080\n")
	os.Exit(2)
}

type Args struct {
	ip       string
	port     string
	sni      string
	proxy    string
	timeout  time.Duration
	dumpPEM  bool
}

func parseArgs() Args {
	a := Args{port: "443", timeout: 7 * time.Second}
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--ip":
			i++; a.ip = must(os.Args, i)
		case "--port":
			i++; a.port = must(os.Args, i)
		case "--sni":
			i++; a.sni = must(os.Args, i)
		case "--proxy":
			i++; a.proxy = must(os.Args, i)
		case "--timeout":
			i++; d, err := time.ParseDuration(must(os.Args, i)); if err != nil { die("Bad --timeout: %v", err) }
			a.timeout = d
		case "--dump-pem":
			a.dumpPEM = true
		case "-h","--help","/?":
			usage()
		default:
			if strings.HasPrefix(os.Args[i], "-") { usage() }
		}
	}
	if a.ip == "" { usage() }
	return a
}

func must(a []string, i int) string { if i>=len(a){ usage() }; return a[i] }
func die(f string, v ...any){ fmt.Fprintf(os.Stderr,"ERROR: "+f+"\n",v...); os.Exit(1) }

func main() {
	args := parseArgs()
	target := net.JoinHostPort(args.ip, args.port)

	// 1) TCP (direct or by proxy)
	rawConn, err := dial(target, args.proxy, args.timeout)
	if err != nil { die("dial: %v", err) }
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(args.timeout))

	// 2) TLS-klient (No verification, No Client certificate). Get the certificate even if the connection could fail later.
	conf := &tls.Config{
		InsecureSkipVerify: true,      // We will inspect only
		ServerName:         args.sni,  // SNI (Empty => No SNI)
		MinVersion:         tls.VersionTLS12, // 1.2 and 1.3
	}
	tconn := tls.Client(rawConn, conf)

	// 3) Handshake – Even if it it fails we may get the PeerCertificates
	err = tconn.Handshake()
	state := tconn.ConnectionState()
	_ = tconn.Close()

	if len(state.PeerCertificates) == 0 {
		if err != nil {
			die("handshake failed before receiving certificate: %v", err)
		}
		die("no server certificate received")
	}

	leaf := state.PeerCertificates[0]
	sum := sha1.Sum(leaf.Raw)

	fmt.Printf("Subject    : %s\n", leaf.Subject.String())
	fmt.Printf("Issuer     : %s\n", leaf.Issuer.String())
	fmt.Printf("CN         : %s\n", leaf.Subject.CommonName)
	fmt.Printf("NotBefore  : %s\n", leaf.NotBefore.UTC().Format(time.RFC3339))
	fmt.Printf("NotAfter   : %s\n", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("Thumbprint : %s\n", strings.ToUpper(hex.EncodeToString(sum[:])))

	if len(leaf.DNSNames) > 0 || len(leaf.IPAddresses) > 0 {
		fmt.Printf("SANs       :")
		for _, d := range leaf.DNSNames { fmt.Printf(" %s", d) }
		for _, ip := range leaf.IPAddresses { fmt.Printf(" %s", ip.String()) }
		fmt.Println()
	}

	if args.dumpPEM {
		fmt.Println("\n--- BEGIN CERTIFICATE CHAIN ---")
		for _, cert := range state.PeerCertificates {
			_ = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
		fmt.Println("--- END CERTIFICATE CHAIN ---")
	}
}

/*** DIAL (DIRECT / PROXY) ***/

func dial(target, proxyURL string, timeout time.Duration) (net.Conn, error) {
	if proxyURL == "" {
		proxyURL = firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy"), os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy"))
	}
	if proxyURL == "" {
		d := net.Dialer{Timeout: timeout}
		return d.Dial("tcp", target)
	}
	u, err := url.Parse(proxyURL); if err != nil { return nil, fmt.Errorf("parse proxy: %w", err) }
	switch strings.ToLower(u.Scheme) {
	case "http","https":
		return dialHTTPProxy(u, target, timeout)
	case "socks5","socks5h":
		return dialSOCKS5(u, target, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}
func firstNonEmpty(s ...string) string { for _,v := range s { if strings.TrimSpace(v)!=""{ return v } }; return "" }

func dialHTTPProxy(u *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if strings.EqualFold(u.Scheme, "https") { host += ":443" } else { host += ":8080" }
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil { return nil, fmt.Errorf("connect proxy: %w", err) }

	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: " + target + "\r\n")
	b.WriteString("Proxy-Connection: Keep-Alive\r\n")
	b.WriteString("User-Agent: TlsPeek/1.0\r\n")

	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		b.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	b.WriteString("\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil { conn.Close(); return nil, fmt.Errorf("read CONNECT response: %w", err) }
	if !strings.Contains(line, " 200 ") {
		hdrs, _ := reader.ReadString('\n')
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s%s", line, hdrs)
	}
	for {
		h, err := reader.ReadString('\n')
		if err != nil { conn.Close(); return nil, fmt.Errorf("read CONNECT headers: %w", err) }
		if h == "\r\n" { break }
	}
	return conn, nil
}

func dialSOCKS5(u *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	host := u.Host
	if !strings.Contains(host, ":") { host += ":1080" }
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil { return nil, fmt.Errorf("connect socks5 proxy: %w", err) }

	// greeting
	methods := []byte{0x00} // no-auth by default
	if u.User != nil { methods = []byte{0x00, 0x02} }
	if _, err := conn.Write([]byte{0x05, byte(len(methods))}); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: write greet head: %w", err) }
	if _, err := conn.Write(methods); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: write greet methods: %w", err) }

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: read method: %w", err) }
	if resp[0] != 0x05 { conn.Close(); return nil, fmt.Errorf("socks5: bad version") }
	if resp[1] == 0x02 {
		// username/password
		if u.User == nil { conn.Close(); return nil, fmt.Errorf("socks5: proxy requires auth") }
		user := u.User.Username()
		pass, _ := u.User.Password()
		if len(user)>255 || len(pass)>255 { conn.Close(); return nil, fmt.Errorf("socks5: credentials too long") }
		buf := []byte{0x01, byte(len(user))}
		buf = append(buf, []byte(user)...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, []byte(pass)...)
		if _, err := conn.Write(buf); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: write auth: %w", err) }
		ab := make([]byte, 2)
		if _, err := io.ReadFull(conn, ab); err != nil || ab[1]!=0x00 {
			conn.Close(); return nil, fmt.Errorf("socks5: auth failed")
		}
	} else if resp[1] != 0x00 {
		conn.Close(); return nil, fmt.Errorf("socks5: no acceptable auth methods")
	}

	// CONNECT command
	hostPart, portStr, err := net.SplitHostPort(target); if err != nil { conn.Close(); return nil, fmt.Errorf("socks5: bad target: %v", err) }
	portNum, _ := net.LookupPort("tcp", portStr)

	cmd := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostPart))}
	cmd = append(cmd, []byte(hostPart)...)
	cmd = append(cmd, byte(portNum>>8), byte(portNum&0xff))
	if _, err := conn.Write(cmd); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: write CONNECT: %w", err) }

	h := make([]byte, 4)
	if _, err := io.ReadFull(conn, h); err != nil { conn.Close(); return nil, fmt.Errorf("socks5: read reply head: %w", err) }
	if h[1] != 0x00 { conn.Close(); return nil, fmt.Errorf("socks5: CONNECT failed, code 0x%02x", h[1]) }

	// consume bound address
	switch h[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4+2); if _, err := io.ReadFull(conn, buf); err != nil { conn.Close(); return nil, err }
	case 0x03: // domain
		lb := make([]byte, 1); if _, err := io.ReadFull(conn, lb); err != nil { conn.Close(); return nil, err }
		rest := make([]byte, int(lb[0])+2); if _, err := io.ReadFull(conn, rest); err != nil { conn.Close(); return nil, err }
	case 0x04: // IPv6
		buf := make([]byte, 16+2); if _, err := io.ReadFull(conn, buf); err != nil { conn.Close(); return nil, err }
	default:
		conn.Close(); return nil, fmt.Errorf("socks5: bad ATYP")
	}
	return conn, nil
}

