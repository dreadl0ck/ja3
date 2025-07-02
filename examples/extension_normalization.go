package main

import (
	"fmt"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
)

func main() {
	// Create a sample ClientHello with randomized extension order
	// This simulates what a modern browser might send
	hello := &tlsx.ClientHelloBasic{
		HandshakeVersion: 0x0303, // TLS 1.2
		CipherSuites: []tlsx.CipherSuite{
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384  
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		},
		AllExtensions: []uint16{
			35,   // session_ticket (randomized order)
			0,    // server_name
			10,   // supported_groups  
			11,   // ec_point_formats
			13,   // signature_algorithms
			16,   // application_layer_protocol_negotiation
			23,   // extended_master_secret
		},
		SupportedGroups: []uint16{
			23, // secp256r1
			24, // secp384r1
			25, // secp521r1
		},
		SupportedPoints: []uint8{
			0, // uncompressed
		},
	}

	fmt.Println("=== JA3 Extension Normalization Demo ===\n")

	// Generate traditional JA3 fingerprint
	traditionalHash := ja3.DigestHex(hello)
	traditionalBare := string(ja3.Bare(hello))
	
	fmt.Printf("Traditional JA3:\n")
	fmt.Printf("  Bare: %s\n", traditionalBare)
	fmt.Printf("  Hash: %s\n\n", traditionalHash)

	// Generate normalized JA3 fingerprint  
	normalizedHash := ja3.DigestHexNormalized(hello)
	normalizedBare := string(ja3.BareNormalized(hello))
	
	fmt.Printf("Normalized JA3:\n")
	fmt.Printf("  Bare: %s\n", normalizedBare)
	fmt.Printf("  Hash: %s\n\n", normalizedHash)

	// Show the difference in extension ordering
	fmt.Printf("Extension Analysis:\n")
	fmt.Printf("  Original order: 35-0-10-11-13-16-23\n")
	fmt.Printf("  Sorted order:   0-10-11-13-16-23-35\n\n")

	// Demonstrate configuration-based approach
	config := &ja3.Config{NormalizeExtensions: true}
	configHash := ja3.DigestHexWithConfig(hello, config)
	
	fmt.Printf("Config-based normalization: %s\n", configHash)
	fmt.Printf("Matches normalized hash: %t\n\n", configHash == normalizedHash)

	// Now simulate the same client with different extension order (browser randomization)
	helloRandomized := &tlsx.ClientHelloBasic{
		HandshakeVersion: hello.HandshakeVersion,
		CipherSuites:     hello.CipherSuites,
		AllExtensions: []uint16{
			13,   // signature_algorithms (different order)
			23,   // extended_master_secret  
			0,    // server_name
			35,   // session_ticket
			10,   // supported_groups
			16,   // application_layer_protocol_negotiation
			11,   // ec_point_formats
		},
		SupportedGroups: hello.SupportedGroups,
		SupportedPoints: hello.SupportedPoints,
	}

	traditionalHashRand := ja3.DigestHex(helloRandomized)
	normalizedHashRand := ja3.DigestHexNormalized(helloRandomized)

	fmt.Printf("=== Randomization Simulation ===\n")
	fmt.Printf("Original traditional hash:    %s\n", traditionalHash)
	fmt.Printf("Randomized traditional hash:  %s\n", traditionalHashRand)
	fmt.Printf("Traditional hashes match:     %t\n\n", traditionalHash == traditionalHashRand)

	fmt.Printf("Original normalized hash:     %s\n", normalizedHash)
	fmt.Printf("Randomized normalized hash:   %s\n", normalizedHashRand)
	fmt.Printf("Normalized hashes match:      %t\n\n", normalizedHash == normalizedHashRand)

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("• Traditional JA3 is broken by extension randomization\n")
	fmt.Printf("• Normalized JA3 is robust against randomization\n")
	fmt.Printf("• Same client produces consistent normalized fingerprints\n")
	fmt.Printf("• Based on research: https://hnull.org/2022/12/01/sorting-out-randomized-tls-fingerprints\n")
}