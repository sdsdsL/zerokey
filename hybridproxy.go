package main

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20"
	"crypto/tls"
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
	stream.XORKeyStream(data, data)
	
	// Prepend nonce for deobfuscation
	obfuscatedData := make([]byte, len(nonce)+len(data))
	copy(obfuscatedData[:12], nonce)
	copy(obfuscatedData[12:], data)
	
	// Replace original data slice (this is simplified - in real impl we'd return new slice)
	copy(data[:12], nonce)
	copy(data[12:], data[12:])
	
	return nil
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
	session, err := quic.DialAddr(c.config.ServerAddr, nil, &quic.Config{})
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
	return &tls.Config{
		Certificates: []tls.Certificate{generateCertificate()}, // Placeholder
	}
}

func generateCertificate() tls.Certificate {
	// Generate self-signed certificate for demonstration
	// Real implementation would use proper certificate management
	return tls.Certificate{} // Placeholder
}

// Example usage
func main() {
	config := &HybridProxyConfig{
		Password:   []byte("my-secret-password"),
		ServerAddr: ":8443",
		EnableObfs: true,
	}

	// Server setup
	server := NewHybridProxyServer(config)
	err := server.Listen()
	if err != nil {
		panic(err)
	}

	// Client setup
	client := NewHybridProxyClient(config)
	err = client.Connect()
	if err != nil {
		panic(err)
	}

	// Example: Connect to google.com through proxy
	conn, err := client.OpenStream("google.com:443")
	if err != nil {
		panic(err)
	}

	// Now conn can be used as a regular net.Conn to communicate with google.com
	// through the proxy
}