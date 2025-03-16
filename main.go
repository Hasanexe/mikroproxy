package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------
// Setup
// -----------------------------------------------------

// Config
type Config struct {
	Port         int
	isSocks      bool
	isDebug      bool
	isLogOff     bool
	LogFile      string
	AllowedIPs   []string
	TCPKeepAlive bool
}

// Logging
var (
	cfg     *Config
	logChan chan string
)

// -----------------------------------------------------
// Main
// -----------------------------------------------------

func main() {
	configPath := flag.String("config", "/etc/mikroproxy.conf", "Path to mikroproxy config file")
	flag.Parse()

	// 2. Load config
	var err error
	cfg, err = loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// 3. Setup async logging
	lf, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer lf.Close()
	logChan = make(chan string, 1000) // Buffer for 1k log entries
	go func() {
		for msg := range logChan {
			timestamp := time.Now().Format("02.01.2006 15:04:05")
			lf.Write([]byte(timestamp + " " + msg + "\n")) // Global log writes
		}
	}()

	// 4. Parse allowed CIDRs
	var networks []*net.IPNet
	for _, cidrStr := range cfg.AllowedIPs {
		ip, ipNet, e := net.ParseCIDR(cidrStr)
		if e != nil {
			logChan <- fmt.Sprintf("Invalid CIDR %q (skipped): %v", cidrStr, e)
			continue
		}
		// skip IPv6
		if ip.To4() == nil {
			logChan <- fmt.Sprintf("Skipping IPv6 CIDR %q", cidrStr)
			continue
		}
		networks = append(networks, ipNet)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logChan <- fmt.Sprintf("Failed to listen on %s: %v", addr, err)
		os.Exit(1)
	}
	defer ln.Close()

	modeStr := "HTTP"
	if cfg.isSocks {
		modeStr = "SOCKS"
	}
	logChan <- fmt.Sprintf("%s: listening on %s", modeStr, addr)

	// 5. Accept loop
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				os.Exit(0)
			}
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("%s: Accept error: %v", modeStr, err)
			}
			continue
		}
		if cfg.TCPKeepAlive {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}
		}

		go func(c net.Conn) {
			defer c.Close()

			remoteAddr, ok := c.RemoteAddr().(*net.TCPAddr)
			if !ok {
				if !cfg.isLogOff {
					logChan <- fmt.Sprintf("%s: Could not parse remote address: %v", modeStr, c.RemoteAddr())
				}
				return
			}

			if !isAllowed(remoteAddr.IP, networks) {
				if !cfg.isLogOff {
					logChan <- fmt.Sprintf("%s: Denying client %s (not in allowed ranges)", modeStr, remoteAddr.IP)
				}
				return
			}

			c.SetReadDeadline(time.Now().Add(10 * time.Second))

			if cfg.isSocks {
				if cfg.isDebug {
					handleSocksDebug(c)
				} else {
					handleSocks(c)
				}
			} else {
				if cfg.isDebug {
					handleHTTPDebug(c)
				} else {
					handleHTTP(c)
				}
			}
		}(conn)
	}
}

// -----------------------------------------------------
// handleHTTP - Forward Proxy for HTTP + CONNECT Tunneling
// -----------------------------------------------------

// ----------------- Debug Mode   ----------------------

func handleHTTPDebug(client net.Conn) {
	defer client.Close()
	logChan <- fmt.Sprintf("%s: New connection", "HTTP")

	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: read error from %s: %v", client.RemoteAddr(), err)
		return
	}
	line = strings.TrimRight(line, "\r\n")
	logChan <- fmt.Sprintf("HTTP: request line from %s: %q", client.RemoteAddr(), line)

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		logChan <- fmt.Sprintf("HTTP: malformed request from %s => 400", client.RemoteAddr())
		return
	}
	method, requestURI, version := parts[0], parts[1], parts[2]

	if strings.ToUpper(method) == "CONNECT" {
		logChan <- fmt.Sprintf("HTTP: CONNECT request => tunnel for %s", client.RemoteAddr())
		handleHTTPConnectDebug(client, reader, requestURI, version)
		return
	}

	// Normal forward-proxy for HTTP method=GET/POST/PUT/DELETE...
	logChan <- fmt.Sprintf("HTTP: forward proxy for method=%s from %s, URI=%s", method, client.RemoteAddr(), requestURI)

	hostPort, newFirstLine, e := parseHostPortFromAbsoluteURI(method, requestURI, version)
	if e != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		logChan <- fmt.Sprintf("HTTP: parseHostPort error for %s: %v", client.RemoteAddr(), e)
		return
	}

	remote, err := net.Dial("tcp", hostPort)
	if cfg.TCPKeepAlive {
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: dial fail %s => %v", hostPort, err)
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()

	// clear read deadline after handshake
	client.SetReadDeadline(time.Time{})

	// If we want to rewrite only the first line to remove the absolute URL
	// In some cases, servers require that. If you want 100% pass-thru, send the original line.
	firstLine := line
	if newFirstLine != "" {
		firstLine = newFirstLine
	}
	remote.Write([]byte(firstLine + "\r\n"))

	// Copy the rest of the request from client to remote
	go func() {
		copyWithPool(remote, reader)
		remote.Close()
	}()

	// Copy response back to client
	copyWithPool(client, remote)

	logChan <- fmt.Sprintf("HTTP: forward done for %s", client.RemoteAddr())
}

func handleHTTPConnectDebug(client net.Conn, reader *bufio.Reader, hostPort, httpVersion string) {
	logChan <- fmt.Sprintf("HTTP: Attempting to tunnel to %s for %s", hostPort, client.RemoteAddr())

	// Read headers until end of headers (blank line)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			logChan <- fmt.Sprintf("HTTP: error reading headers from %s: %v", client.RemoteAddr(), err)
			io.WriteString(client, httpVersion+" 500 Internal Server Error\r\n\r\n")
			return
		}
		// Check for end of headers (blank line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	remote, err := net.Dial("tcp", hostPort)
	if cfg.TCPKeepAlive {
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	if err != nil {
		logChan <- fmt.Sprintf("HTTP: Failed to connect to %s for %s: %v", hostPort, client.RemoteAddr(), err)
		io.WriteString(client, httpVersion+" 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()

	// Send 200 response
	io.WriteString(client, httpVersion+" 200 Connection Established\r\n\r\n")

	client.SetReadDeadline(time.Time{})

	logChan <- fmt.Sprintf("HTTP: tunnel established %s <-> %s", client.RemoteAddr(), hostPort)

	// Relay data
	go copyWithPool(remote, reader)
	copyWithPool(client, remote)

	logChan <- fmt.Sprintf("HTTP: tunnel closed %s <-> %s", client.RemoteAddr(), hostPort)
}

// ----------------- Normal Mode   ----------------------

func handleHTTP(client net.Conn) {
	defer client.Close()
	reader := bufio.NewReader(client)

	line, err := reader.ReadString('\n')
	if err != nil {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("HTTP: read error from %s: %v", client.RemoteAddr(), err)
		}
		return
	}
	line = strings.TrimRight(line, "\r\n")

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	method, requestURI, version := parts[0], parts[1], parts[2]

	if strings.ToUpper(method) == "CONNECT" {
		handleHTTPConnect(client, reader, requestURI, version)
		return
	}

	hostPort, newFirstLine, e := parseHostPortFromAbsoluteURI(method, requestURI, version)
	if e != nil {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	remote, err := net.Dial("tcp", hostPort)
	if cfg.TCPKeepAlive {
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()

	// clear read deadline after handshake
	client.SetReadDeadline(time.Time{})

	// If we want to rewrite only the first line to remove the absolute URL
	// In some cases, servers require that. If you want 100% pass-thru, send the original line.
	firstLine := line
	if newFirstLine != "" {
		firstLine = newFirstLine
	}
	remote.Write([]byte(firstLine + "\r\n"))

	// Copy the rest of the request from client to remote
	go func() {
		copyWithPool(remote, reader)
		remote.Close()
	}()

	// Copy response back to client
	copyWithPool(client, remote)

	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("HTTP: forward done for %s", client.RemoteAddr())
	}
}

func handleHTTPConnect(client net.Conn, reader *bufio.Reader, hostPort, httpVersion string) {
	// Read headers until end of headers (blank line)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			io.WriteString(client, httpVersion+" 500 Internal Server Error\r\n\r\n")
			return
		}
		// Check for end of headers (blank line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	remote, err := net.Dial("tcp", hostPort)
	if cfg.TCPKeepAlive {
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	if err != nil {
		io.WriteString(client, httpVersion+" 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()

	// Send 200 response
	io.WriteString(client, httpVersion+" 200 Connection Established\r\n\r\n")

	client.SetReadDeadline(time.Time{})
	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("HTTP: tunnel established %s <-> %s", client.RemoteAddr(), hostPort)
	}

	// Relay data
	go copyWithPool(remote, reader)
	copyWithPool(client, remote)
}

func parseHostPortFromAbsoluteURI(method, requestURI, httpVersion string) (hostPort, newFirstLine string, err error) {
	u, e := url.Parse(requestURI)
	if e != nil {
		return "", "", fmt.Errorf("url parse error: %v", e)
	}
	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostPort = net.JoinHostPort(host, port)

	// If you want minimal rewriting so the server sees "GET /path HTTP/1.1" instead of absolute
	// If you want total pass-thru, set newFirstLine = "" so caller uses the original line
	newFirstLine = fmt.Sprintf("%s %s %s", method, u.RequestURI(), httpVersion)

	return hostPort, newFirstLine, nil
}

// -----------------------------------------------------
// SOCKS5 Handler (Debug)
// -----------------------------------------------------

// ----------------- Debug Mode   ----------------------

func handleSocksDebug(client net.Conn) {
	logChan <- fmt.Sprintf("%s: New connection", "SOCKS")

	defer client.Close()

	remoteAddr := client.RemoteAddr()
	logChan <- fmt.Sprintf("SOCKS: Starting handshake with %s", remoteAddr)

	var buf [256]byte
	// read (VER, NMETHODS, METHODS...)
	n, err := io.ReadAtLeast(client, buf[:], 2)
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: handshake error from %s: %v", remoteAddr, err)
		return
	}
	ver := buf[0]
	if ver != 0x05 {
		logChan <- fmt.Sprintf("SOCKS: Invalid version %d from %s", ver, remoteAddr)
		return
	}
	methodsCount := int(buf[1])
	logChan <- fmt.Sprintf("SOCKS: ver=5, methodsCount=%d from %s", methodsCount, remoteAddr)

	need := 2 + methodsCount
	if n < need {
		if _, err := io.ReadFull(client, buf[n:need]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: reading methods error from %s: %v", remoteAddr, err)
			return
		}
	}

	// respond no auth
	_, err = client.Write([]byte{0x05, 0x00})
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: handshake write error to %s: %v", remoteAddr, err)
		return
	}
	logChan <- fmt.Sprintf("SOCKS: handshake done with %s", remoteAddr)

	// read (VER,CMD,RSV,ATYP)
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		logChan <- fmt.Sprintf("SOCKS: request header error from %s: %v", remoteAddr, err)
		return
	}
	version, cmd, rsv, addrType := buf[0], buf[1], buf[2], buf[3]
	logChan <- fmt.Sprintf("SOCKS: request version=%d, cmd=%d, rsv=%d, addrType=%d from %s", version, cmd, rsv, addrType, remoteAddr)

	if version != 0x05 || cmd != 0x01 {
		logChan <- fmt.Sprintf("SOCKS: unsupported request (ver=%d, cmd=%d) from %s", version, cmd, remoteAddr)
		client.Write([]byte{0x05, 0x07, 0x00, 0x01})
		return
	}

	// parse destination
	var dstIP net.IP
	var dstStr string

	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: IPv4 read error from %s: %v", remoteAddr, err)
			return
		}
		dstIP = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		dstStr = dstIP.String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: domain length error from %s: %v", remoteAddr, err)
			return
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			logChan <- fmt.Sprintf("SOCKS: domain read error from %s: %v", remoteAddr, err)
			return
		}
		domain := string(buf[:domainLen])
		addrs, e := net.LookupIP(domain)
		if e != nil || len(addrs) == 0 {
			logChan <- fmt.Sprintf("SOCKS: domain resolve fail %s from %s: %v", domain, remoteAddr, e)
			client.Write([]byte{0x05, 0x04, 0x00, 0x01})
			return
		}
		found := false
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				dstIP = v4
				dstStr = domain
				found = true
				break
			}
		}
		if !found {
			logChan <- fmt.Sprintf("SOCKS: no IPv4 found for domain=%s from %s", domain, remoteAddr)
			client.Write([]byte{0x05, 0x08, 0x00, 0x01})
			return
		}
	case 0x04:
		logChan <- fmt.Sprintf("SOCKS: IPv6 not supported from %s", remoteAddr)
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	default:
		logChan <- fmt.Sprintf("SOCKS: unknown addrType=%d from %s", addrType, remoteAddr)
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	}

	// read port
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		logChan <- fmt.Sprintf("SOCKS: port read error from %s: %v", remoteAddr, err)
		return
	}
	dstPort := binary.BigEndian.Uint16(buf[:2])

	logChan <- fmt.Sprintf("SOCKS: CONNECT to %s:%d from %s", dstStr, dstPort, remoteAddr)

	// dial
	targetAddr := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: fail connect %s for %s: %v", targetAddr, remoteAddr, err)
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// success
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		logChan <- fmt.Sprintf("SOCKS: fail sending success to %s: %v", remoteAddr, err)
		return
	}
	logChan <- fmt.Sprintf("SOCKS: tunnel established %s <-> %s:%d", remoteAddr, dstStr, dstPort)

	client.SetReadDeadline(time.Time{})

	go copyWithPool(remote, client)
	copyWithPool(client, remote)

	logChan <- fmt.Sprintf("SOCKS: tunnel closed %s <-> %s:%d", remoteAddr, dstStr, dstPort)
}

// ----------------- Normal Mode   ----------------------

func handleSocks(client net.Conn) {
	defer client.Close()

	remoteAddr := client.RemoteAddr()

	var buf [256]byte
	// read (VER, NMETHODS, METHODS...)
	n, err := io.ReadAtLeast(client, buf[:], 2)
	if err != nil {
		return
	}
	ver := buf[0]
	if ver != 0x05 {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: Invalid version %d from %s", ver, remoteAddr)
		}
		return
	}
	methodsCount := int(buf[1])

	need := 2 + methodsCount
	if n < need {
		if _, err := io.ReadFull(client, buf[n:need]); err != nil {
			return
		}
	}

	// respond no auth
	_, err = client.Write([]byte{0x05, 0x00})
	if err != nil {
		return
	}

	// read (VER,CMD,RSV,ATYP)
	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: request header error from %s: %v", remoteAddr, err)
		}
		return
	}
	version, cmd, _, addrType := buf[0], buf[1], buf[2], buf[3]

	if version != 0x05 || cmd != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01})
		return
	}

	// parse destination
	var dstIP net.IP
	var dstStr string

	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		dstIP = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		dstStr = dstIP.String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			return
		}
		domain := string(buf[:domainLen])
		addrs, e := net.LookupIP(domain)
		if e != nil || len(addrs) == 0 {
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("SOCKS: domain resolve fail %s from %s: %v", domain, remoteAddr, e)
			}
			client.Write([]byte{0x05, 0x04, 0x00, 0x01})
			return
		}
		found := false
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				dstIP = v4
				dstStr = domain
				found = true
				break
			}
		}
		if !found {
			if !cfg.isLogOff {
				logChan <- fmt.Sprintf("SOCKS: no IPv4 found for domain=%s from %s", domain, remoteAddr)
			}
			client.Write([]byte{0x05, 0x08, 0x00, 0x01})
			return
		}
	case 0x04:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	default:
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: unknown addrType=%d from %s", addrType, remoteAddr)
		}
		client.Write([]byte{0x05, 0x08, 0x00, 0x01})
		return
	}

	// read port
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		if !cfg.isLogOff {
			logChan <- fmt.Sprintf("SOCKS: port read error from %s: %v", remoteAddr, err)
		}
		return
	}
	dstPort := binary.BigEndian.Uint16(buf[:2])

	// dial
	targetAddr := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// success
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return
	}
	if !cfg.isLogOff {
		logChan <- fmt.Sprintf("SOCKS: tunnel established %s <-> %s:%d", remoteAddr, dstStr, dstPort)
	}

	client.SetReadDeadline(time.Time{})

	go copyWithPool(remote, client)
	copyWithPool(client, remote)
}

// -----------------------------------------------------
// isAllowed
// -----------------------------------------------------

func isAllowed(ip net.IP, networks []*net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, n := range networks {
		if n.Contains(ip4) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------
// Buffer Pooling
// -----------------------------------------------------

var (
	bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB buffer
		},
	}
)

func copyWithPool(dst io.Writer, src io.Reader) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	io.CopyBuffer(dst, src, buf)
}

// -----------------------------------------------------
// loadConfig
// -----------------------------------------------------

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Default config with mode=socks, port=3128
	cfg := &Config{
		isSocks:      false,                     //proxy_mode   = http
		isDebug:      false,                     //log_level    = debug
		isLogOff:     false,                     //log_level    = off || none
		Port:         3128,                      //port             = 3128
		AllowedIPs:   []string{},                //allowed_ip   = 0.0.0.0/0 (cidr)
		TCPKeepAlive: false,                     //tcpkeepalive = 1 || on
		LogFile:      "/var/log/mikroproxy.log", //log_file
	}

	var content strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			content.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	lines := strings.Split(content.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "proxy_mode":
			cfg.isSocks = strings.HasPrefix(strings.ToLower(val), "socks")
		case "port":
			var p int
			fmt.Sscanf(val, "%d", &p)
			if p > 0 && p < 65536 {
				cfg.Port = p
			}
		case "log_file":
			cfg.LogFile = val
		case "log_level":
			logLevel := strings.ToLower(val)
			cfg.isDebug = logLevel == "debug"
			cfg.isLogOff = logLevel == "off" || logLevel == "none"
		case "allowed_ip":
			cfg.AllowedIPs = append(cfg.AllowedIPs, val)
		case "tcpkeepalive":
			cfg.TCPKeepAlive = val == "1" || strings.ToLower(val) == "on"
		}
	}
	return cfg, nil
}
