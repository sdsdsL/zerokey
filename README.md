# HybridProxy Protocol Design Document

## Overview

HybridProxy is a custom networking protocol that combines the best features of Hysteria2 (QUIC/UDP transport, congestion control, salamander obfuscation) and VLESS (minimalist headers, direct payload delivery). It aims to provide fast, censorship-resistant communication while maintaining low overhead.

## Architecture

```
Client Application → VLESS-style Minimal Headers → Salamander Obfuscation → QUIC/UDP Transport → Server
                                                                                          ↓
                                                                               Target Server Connection
```

## Key Features

### Transport Layer
- **QUIC over UDP**: Uses QUIC for its built-in encryption, multiplexing, and loss resistance
- **Custom Congestion Control**: Inspired by Hysteria's BBR implementation for better performance over lossy links
- **Support for TCP/UDP Proxying**: Handles both protocols transparently through QUIC streams

### Obfuscation Layer
- **Salamander-style Scrambling**: Password-based ChaCha20 scrambling to prevent pattern recognition
- **uTLS Fingerprint Randomization**: Mimics legitimate TLS clients to avoid DPI detection
- **Adaptive Packet Size**: Adjusts packet sizes to match normal TLS patterns

### Payload Format
- **Minimal VLESS-style Headers**: Just enough information to route (target address, port)
- **No Extra Metadata**: Reduces overhead and analysis surface
- **Direct Mode**: Inspired by VLESS Vision, eliminates handshake overhead

### Authentication
- **Shared Secret**: Simple password-based authentication (no PKI overhead)
- **Optional Certificate Validation**: For environments requiring stronger security

## Protocol Flow

### Client Side
1. Establish QUIC connection to server with uTLS mimicry
2. For each connection request:
   - Build minimal VLESS-style header with target address
   - Apply salamander obfuscation using shared password
   - Send header via QUIC stream
   - Forward application data through stream

### Server Side
1. Accept QUIC connection with proper TLS mimicry
2. For each incoming stream:
   - Receive and deobfuscate minimal header
   - Parse target address from header
   - Establish connection to target server
   - Relay data bidirectionally

## Implementation Details

### Core Components

```go
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

// VLESSParser handles minimal VLESS-style header parsing
type VLESSParser struct{}
```

### Obfuscation Algorithm

The protocol uses ChaCha20-based scrambling similar to Hysteria's salamander:

1. Derive 32-byte key from shared password
2. Generate random 12-byte nonce
3. Create keystream using ChaCha20 with key and nonce
4. XOR data with keystream
5. Prepend nonce to scrambled data for deobfuscation

### Header Format

The minimal header follows VLESS principles:

```
[Version: 1 byte][Address Type: 1 nibble][Reserved: 7 bits][Address Length: 1 byte][Address Data][Port: 2 bytes]
```

## Security Considerations

### Strengths
- **Traffic Mimicry**: QUIC with TLS mimicry looks like legitimate HTTPS traffic
- **Pattern Obfuscation**: Salamander scrambling prevents signature-based detection
- **Low Overhead**: Minimal headers reduce analysis surface

### Weaknesses
- **Shared Secret**: Single password compromise affects all connections
- **Timing Analysis**: Traffic patterns may still reveal proxy usage
- **Implementation Leaks**: Improper implementation may leak information

## Testing Strategy

### DPI Evasion Testing
- Use tools like ICLAB's DPI emulator to test against known detection rules
- Test with various uTLS fingerprints to ensure TLS mimicry effectiveness
- Analyze packet timing and size distributions for patterns

### Performance Testing
- Compare throughput against baseline protocols (TCP, standard QUIC)
- Test under various network conditions (high loss, variable latency)
- Measure CPU/memory overhead of obfuscation layers

### Censorship Resistance Testing
- Deploy in known censored environments for real-world validation
- Monitor for blocking patterns and adapt accordingly
- Test resilience to active probing attacks

## Trade-offs

### Speed vs Security
- Prioritizes speed by using simple shared-key authentication
- Sacrifices some security properties for better performance
- Uses minimal encryption for payload (relying on QUIC transport security)

### Complexity vs Efficacy
- Simpler implementation reduces potential bugs and analysis surface
- Less complex obfuscation may be easier to detect over time
- Balances between effective censorship resistance and maintainability

## Future Enhancements

- **Pluggable Transports**: Support for alternative obfuscation methods
- **Automatic Fallback**: Integration with fallback servers for enhanced reliability
- **Advanced Congestion Control**: Adaptive algorithms based on network conditions
- **Quantum-Resistant Crypto**: Post-quantum algorithms for long-term security
