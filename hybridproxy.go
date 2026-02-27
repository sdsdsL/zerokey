package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20"
)

// Constants for the protocol
const (
	ProtocolVersion = 0x01
	MaxPacketSize   = 1500
	HeaderLength    = 8 // Minimal VLESS-style header
)

// HybridProxyConfig holds configuration for both client and server
type HybridProxyConfig struct {
	Password       []byte
	ServerAddr     string
	Transport      string // "tcp" or "udp"
	EnableObfs     bool
	UTLSFingerprint string // For mimicking various TLS clients
}

// SalamanderObfuscator implements the salamander-like obfuscation
type SalamanderObfuscator struct {
	password []byte
}

// NewSalamanderObfuscator creates a new obfuscator instance
func NewSalamanderObfuscator(password []byte) *SalamanderObfuscator {
	return &SalamanderObfuscator{
		password: password,
	}
}

// Obfuscate applies salamander-style scrambling to data
func (s *SalamanderObfuscator) Obfuscate(data []byte) error {
	if len(s.password) == 0 {
		return nil // No obfuscation if no password
	}

	key := make([]byte, 32)
	copy(key, s.password)
	
	// Use ChaCha20 for scrambling
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	// Apply keystream to data
	obfuscatedPayload := make([]byte, len(data))
	stream.XORKeyStream(obfuscatedPayload, data)
	
	// Prepend nonce for deobfuscation
	obfuscatedData := make([]byte, len(nonce)+len(obfuscatedPayload))
	copy(obfuscatedData[:12], nonce)
	copy(obfuscatedData[12:], obfuscatedPayload)
	
	// Copy back to original slice if large enough, otherwise return error
	if len(data) >= len(obfuscatedData) {
		copy(data[:len(obfuscatedData)], obfuscatedData)
		return nil
	} else {
		// If the original data slice is too small, return an error
		return fmt.Errorf("data buffer too small for obfuscated data")
	}
}

// Deobfuscate reverses the salamander scrambling
func (s *SalamanderObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	if len(s.password) == 0 || len(data) < 12 {
		return data, nil
	}

	nonce := data[:12]
	payload := data[12:]

	key := make([]byte, 32)
	copy(key, s.password)

	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	// Apply keystream to get original data
	result := make([]byte, len(payload))
	stream.XORKeyStream(result, payload)
	
	return result, nil
}

// VLESSParser handles minimal VLESS-style header parsing
type VLESSParser struct{}

// ParseAddress extracts target address from minimal header
func (v *VLESSParser) ParseAddress(header []byte) (string, error) {
	if len(header) < HeaderLength {
		return "", fmt.Errorf("header too short")
	}

	// Simplified address parsing - in real impl would handle various formats
	addrType := header[0] & 0x0F
	addrLen := int(header[1])
	
	if len(header) < 2+addrLen {
		return "", fmt.Errorf("address field too short")
	}

	var addr string
	switch addrType {
	case 1: // IPv4
		ip := net.IP(header[2 : 2+net.IPv4len])
		port := uint16(header[2+net.IPv4len])<<8 | uint16(header[2+net.IPv4len+1])
		addr = fmt.Sprintf("%s:%d", ip.String(), port)
	case 2: // Domain
		domain := string(header[2 : 2+addrLen])
		port := uint16(header[2+addrLen])<<8 | uint16(header[2+addrLen+1])
		addr = fmt.Sprintf("%s:%d", domain, port)
	case 3: // IPv6
		ip := net.IP(header[2 : 2+net.IPv6len])
		port := uint16(header[2+net.IPv6len])<<8 | uint16(header[2+net.IPv6len+1])
		addr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	return addr, nil
}

// BuildRequest creates minimal VLESS-style header
func (v *VLESSParser) BuildRequest(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}

	port := 80
	fmt.Sscanf(portStr, "%d", &port)

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		header := make([]byte, 2+len(host)+2)
		header[0] = 0x02 // Domain type
		header[1] = byte(len(host)) // Length
		copy(header[2:], host)
		header[2+len(host)] = byte(port >> 8)
		header[2+len(host)+1] = byte(port & 0xFF)
		return header, nil
	} else if ip.To4() != nil {
		// IPv4
		header := make([]byte, 2+net.IPv4len+2)
		header[0] = 0x01 // IPv4 type
		header[1] = byte(net.IPv4len)
		copy(header[2:], ip.To4())
		header[2+net.IPv4len] = byte(port >> 8)
		header[2+net.IPv4len+1] = byte(port & 0xFF)
		return header, nil
	} else {
		// IPv6
		header := make([]byte, 2+net.IPv6len+2)
		header[0] = 0x03 // IPv6 type
		header[1] = byte(net.IPv6len)
		copy(header[2:], ip.To16())
		header[2+net.IPv6len] = byte(port >> 8)
		header[2+net.IPv6len+1] = byte(port & 0xFF)
		return header, nil
	}
}

// HybridProxyClient implements the client side
type HybridProxyClient struct {
	config    *HybridProxyConfig
	obfuscator *SalamanderObfuscator
	parser    *VLESSParser
	session   quic.Session
}

// NewHybridProxyClient creates a new client instance
func NewHybridProxyClient(config *HybridProxyConfig) *HybridProxyClient {
	return &HybridProxyClient{
		config:     config,
		obfuscator: NewSalamanderObfuscator(config.Password),
		parser:     &VLESSParser{},
	}
}

// Connect establishes connection to server
func (c *HybridProxyClient) Connect() error {
	// Create QUIC session (with uTLS mimicry in real implementation)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // For self-signed certificates
		NextProtos:         []string{"hq-29", "h3-29", "h3"}, // Match server
	}
	session, err := quic.DialAddr(c.config.ServerAddr, &quic.Config{}, tlsConf)
	if err != nil {
		return err
	}
	c.session = session
	
	return nil
}

// OpenStream creates a new stream to target address
func (c *HybridProxyClient) OpenStream(targetAddr string) (net.Conn, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, err
	}

	// Build VLESS-style request header
	req, err := c.parser.BuildRequest(targetAddr)
	if err != nil {
		stream.Close()
		return nil, err
	}

	// Apply obfuscation if enabled
	if c.config.EnableObfs {
		err = c.obfuscator.Obfuscate(req)
		if err != nil {
			stream.Close()
			return nil, err
		}
	}

	// Send header first
	_, err = stream.Write(req)
	if err != nil {
		stream.Close()
		return nil, err
	}

	return &hybridProxyConn{stream: stream}, nil
}

// hybridProxyConn wraps QUIC stream to implement net.Conn interface
type hybridProxyConn struct {
	stream quic.Stream
}

func (h *hybridProxyConn) Read(b []byte) (n int, err error) {
	return h.stream.Read(b)
}

func (h *hybridProxyConn) Write(b []byte) (n int, err error) {
	return h.stream.Write(b)
}

func (h *hybridProxyConn) Close() error {
	return h.stream.Close()
}

func (h *hybridProxyConn) LocalAddr() net.Addr {
	return nil // Not implemented
}

func (h *hybridProxyConn) RemoteAddr() net.Addr {
	return nil // Not implemented
}

func (h *hybridProxyConn) SetDeadline(t time.Time) error {
	return nil // Not implemented
}

func (h *hybridProxyConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented
}

func (h *hybridProxyConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented
}

// HybridProxyServer implements the server side
type HybridProxyServer struct {
	config     *HybridProxyConfig
	obfuscator *SalamanderObfuscator
	parser     *VLESSParser
	listener   quic.Listener
}

// NewHybridProxyServer creates a new server instance
func NewHybridProxyServer(config *HybridProxyConfig) *HybridProxyServer {
	return &HybridProxyServer{
		config:     config,
		obfuscator: NewSalamanderObfuscator(config.Password),
		parser:     &VLESSParser{},
	}
}

// Listen starts the server
func (s *HybridProxyServer) Listen() error {
	listener, err := quic.ListenAddr(s.config.ServerAddr, generateTLSConfig(), &quic.Config{})
	if err != nil {
		return err
	}
	s.listener = listener
	
	go s.handleConnections()
	
	return nil
}

// handleConnections accepts and handles incoming connections
func (s *HybridProxyServer) handleConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			continue // Log error in real implementation
		}
		
		go s.handleConnection(conn)
	}
}

// handleConnection processes a single QUIC connection
func (s *HybridProxyServer) handleConnection(session quic.Session) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			break // Connection closed
		}
		
		go s.handleStream(stream)
	}
}

// handleStream processes a single stream
func (s *HybridProxyServer) handleStream(stream quic.Stream) {
	defer stream.Close()

	// Read the minimal header
	header := make([]byte, HeaderLength*2) // Allow for larger headers
	n, err := stream.Read(header)
	if err != nil {
		return
	}
	header = header[:n]

	// Deobfuscate if enabled
	if s.config.EnableObfs {
		header, err = s.obfuscator.Deobfuscate(header)
		if err != nil {
			return
		}
	}

	// Parse target address
	targetAddr, err := s.parser.ParseAddress(header)
	if err != nil {
		return
	}

	// Connect to target
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Relay data between stream and target
	go func() {
		io.Copy(stream, targetConn)
		stream.Close()
	}()
	
	io.Copy(targetConn, stream)
}

// Helper function to generate TLS config (simplified)
func generateTLSConfig() *tls.Config {
	// In real implementation, this would use uTLS with randomized fingerprints
	cert := generateCertificate()
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"hq-29", "h3-29", "h3"}, // Common QUIC ALPN values
	}
}

func generateCertificate() tls.Certificate {
	// Generate a self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate private key:", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"HybridProxy"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

// Example usage
func main() {
	config := &HybridProxyConfig{
		Password:   []byte("my-secret-password"),
		ServerAddr: "localhost:8443",
		EnableObfs: true,
	}

	// Start server in a goroutine
	server := NewHybridProxyServer(config)
	err := server.Listen()
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
	log.Println("Server started on", config.ServerAddr)

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Start client
	client := NewHybridProxyClient(config)
	err = client.Connect()
	if err != nil {
		log.Fatal("Client failed to connect:", err)
	}
	log.Println("Client connected to server")

	// Example: Connect to google.com through proxy
	conn, err := client.OpenStream("google.com:443")
	if err != nil {
		log.Fatal("Failed to open stream:", err)
	}
	log.Println("Stream opened to google.com:443")

	// Send a simple HTTPS request
	request := "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		log.Fatal("Failed to write request:", err)
	}
	log.Println("Request sent")

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		log.Println("Error reading response:", err)
	} else {
		log.Printf("Received %d bytes: %.100s", n, string(response[:n]))
	}

	// Clean up
	conn.Close()
}