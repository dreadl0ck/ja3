/*
 * JA3 - TLS Client Hello Hash
 * Copyright (c) 2017, Salesforce.com, Inc.
 * this code was created by Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ja3

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var tlsPacket = []byte{
	0x68, 0x7f, 0x74, 0xd6, 0x95, 0xc1, 0x00, 0x22, 0x15, 0x63, 0xc9, 0x5a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0xe5, 0x0f, 0xf0, 0x40, 0x00, 0x80, 0x06, 0xaf, 0x9d, 0xc0, 0xa8, 0x01, 0x0e, 0x17, 0x17,
	0x61, 0xb8, 0xc0, 0xef, 0x01, 0xbb, 0x49, 0x71, 0x37, 0x25, 0x98, 0x36, 0xf3, 0x06, 0x50, 0x18,
	0x01, 0x00, 0xfe, 0xf4, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0xb8, 0x01, 0x00, 0x00, 0xb4, 0x03,
	0x03, 0x59, 0xc1, 0x47, 0x24, 0x67, 0x4d, 0x4f, 0x3b, 0x1f, 0xbd, 0x36, 0x75, 0x9b, 0x2a, 0x92,
	0x47, 0x45, 0xf6, 0x7b, 0x03, 0x19, 0x09, 0x13, 0x76, 0x7e, 0xfc, 0x7f, 0xc4, 0x22, 0x6b, 0xe8,
	0x1a, 0x20, 0xfb, 0xa8, 0x85, 0x7c, 0x99, 0xca, 0x36, 0x12, 0xe7, 0x72, 0xb0, 0x87, 0xef, 0xdd,
	0x08, 0x02, 0x7f, 0xc7, 0x55, 0x72, 0xdc, 0x5a, 0xeb, 0x7b, 0x1f, 0x04, 0x61, 0xf4, 0xa6, 0x82,
	0x18, 0x51, 0x00, 0x2a, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x05, 0x00, 0x0a,
	0xc0, 0x27, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x23, 0xc0, 0x2c, 0xc0, 0x24, 0xc0, 0x09,
	0xc0, 0x0a, 0x00, 0x40, 0x00, 0x32, 0x00, 0x6a, 0x00, 0x38, 0x00, 0x13, 0x00, 0x04, 0x01, 0x00,
	0x00, 0x41, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f,
	0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x2e, 0x6b, 0x72, 0x78, 0x64, 0x2e, 0x6e, 0x65, 0x74, 0x00,
	0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
	0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02,
	0x03, 0x02, 0x02,
}

func getHello(p gopacket.Packet, b *testing.B) (hello *tlsx.ClientHelloBasic) {
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				b.Fatal("Connection setup")
			} else if tcp.FIN {
				b.Fatal("Connection teardown")
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				b.Fatal("Acknowledgement packet")
			} else if tcp.RST {
				b.Fatal("Unexpected packet")
			} else {
				hello = &tlsx.ClientHelloBasic{}
				err := hello.Unmarshal(tcp.LayerPayload())
				if err != nil {
					b.Fatal("invalid packet", err)
				}
			}
		}
	}
	return
}

/*
 *	Tests
 */

func TestDigestHexCorrect(t *testing.T) {

	p := gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Lazy)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}

	hash := DigestHexPacket(p)
	if hash != "4d7a28d6f2263ed61de88ca66eb011e3" {
		t.Fatal(hash, "!=", "4d7a28d6f2263ed61de88ca66eb011e3")
	}
}

func TestNormalizedFingerprinting(t *testing.T) {
	// Test that normalized and regular fingerprints work correctly
	p := gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Lazy)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}

	// Get fingerprints with different configurations
	regularHash := DigestHexPacket(p)
	normalizedHash := DigestHexPacketNormalized(p)
	
	// Both should be valid hashes
	if len(regularHash) != 32 {
		t.Fatal("Regular hash should be 32 characters, got:", len(regularHash))
	}
	if len(normalizedHash) != 32 {
		t.Fatal("Normalized hash should be 32 characters, got:", len(normalizedHash))
	}

	// Test with configuration objects
	config := &Config{NormalizeExtensions: false}
	configHash := DigestHexPacketWithConfig(p, config)
	if configHash != regularHash {
		t.Fatal("Config hash should match regular hash")
	}

	configNormalized := &Config{NormalizeExtensions: true}
	configNormalizedHash := DigestHexPacketWithConfig(p, configNormalized)
	if configNormalizedHash != normalizedHash {
		t.Fatal("Config normalized hash should match normalized hash")
	}
}

func TestExtensionSorting(t *testing.T) {
	// Create a test ClientHello with known extensions in specific order
	hello := &tlsx.ClientHelloBasic{
		HandshakeVersion: 0x0303,
		AllExtensions: []uint16{
			35,  // session_ticket 
			0,   // server_name
			10,  // supported_groups
			11,  // ec_point_formats
			13,  // signature_algorithms
		},
	}

	// Get bare strings with and without normalization
	regularBare := string(Bare(hello))
	normalizedBare := string(BareNormalized(hello))

	// Regular should have extensions in original order: 35-0-10-11-13
	// Normalized should have extensions sorted: 0-10-11-13-35
	if !containsSubstring(regularBare, "35-0-10-11-13") {
		t.Fatal("Regular bare should contain extensions in original order, got:", regularBare)
	}
	if !containsSubstring(normalizedBare, "0-10-11-13-35") {
		t.Fatal("Normalized bare should contain extensions in sorted order, got:", normalizedBare)
	}

	// Test with configuration
	config := &Config{NormalizeExtensions: true}
	configBare := string(BareWithConfig(hello, config))
	if configBare != normalizedBare {
		t.Fatal("Config-based normalization should match convenience function")
	}
}

func TestConfigNil(t *testing.T) {
	// Test that nil config uses default behavior
	hello := &tlsx.ClientHelloBasic{
		HandshakeVersion: 0x0303,
		AllExtensions: []uint16{
			35,  
			0,   
		},
	}

	regularBare := string(Bare(hello))
	nilConfigBare := string(BareWithConfig(hello, nil))

	if regularBare != nilConfigBare {
		t.Fatal("Nil config should behave same as default config")
	}
}

func TestGreaseFiltering(t *testing.T) {
	// Test that GREASE values are filtered correctly in both modes
	hello := &tlsx.ClientHelloBasic{
		HandshakeVersion: 0x0303,
		AllExtensions: []uint16{
			0x0a0a, // GREASE value - should be filtered
			0,      // server_name - should be kept
			0x1a1a, // GREASE value - should be filtered
			10,     // supported_groups - should be kept
		},
	}

	regularBare := string(Bare(hello))
	normalizedBare := string(BareNormalized(hello))

	// Both should only contain non-GREASE extensions (0 and 10)
	if containsSubstring(regularBare, "2570") || containsSubstring(regularBare, "6666") { // 0x0a0a and 0x1a1a in decimal
		t.Fatal("Regular bare should not contain GREASE values, got:", regularBare)
	}
	if containsSubstring(normalizedBare, "2570") || containsSubstring(normalizedBare, "6666") {
		t.Fatal("Normalized bare should not contain GREASE values, got:", normalizedBare)
	}

	// Both should contain the non-GREASE extensions
	if !containsSubstring(regularBare, "0") || !containsSubstring(regularBare, "10") {
		t.Fatal("Regular bare should contain non-GREASE extensions, got:", regularBare)
	}
	if !containsSubstring(normalizedBare, "0") || !containsSubstring(normalizedBare, "10") {
		t.Fatal("Normalized bare should contain non-GREASE extensions, got:", normalizedBare)
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findInString(s, substr) != -1
}

// Helper function to find substring in string (simple implementation)
func findInString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestDigestHexComparePcap(t *testing.T) {

	// Step 1: Read JSON output of reference implementation
	data, err := ioutil.ReadFile("ja3_output_testpcap.json")
	if err != nil {
		t.Fatal(err)
	}

	var referenceRecords = make([]*Record, 0)
	err = json.Unmarshal(data, &referenceRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: generate JSON output wth goja3 and read into buffer
	var (
		b       bytes.Buffer
		records = make([]*Record, 0)
	)

	// read test.pcap and generate fingerprints
	ReadFileJSON("test.pcap", &b, false)

	err = json.Unmarshal(b.Bytes(), &records)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: compare the number of fingerprints and then the digest for each record
	if len(records) != len(referenceRecords) {
		t.Fatal("len(records) != len(referenceRecords): ", len(records), " != ", len(referenceRecords))
	}

	// range reference records
	for i, r := range referenceRecords {

		// compare reference digest to the one produced by goja3
		if r.JA3Digest != records[i].JA3Digest {
			t.Fatal("r.JA3Digest != records[i].JA3Digest: ", r.JA3Digest, " != ", records[i].JA3Digest)
		}
		// compare reference digest to the one produced by goja3
		if r.JA3SDigest != records[i].JA3SDigest {
			t.Fatal("r.JA3SDigest != records[i].JAS3Digest: ", r.JA3SDigest, " != ", records[i].JA3SDigest)
		}
	}
}

/*
 *	Benchmarks
 */

func BenchmarkDigestHexPacket(b *testing.B) {

	p := gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Default)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestHexPacket(p)
	}
}

func BenchmarkDigestPacket(b *testing.B) {
	p := gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		b.Fatal(p.ErrorLayer().Error())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestPacket(p)
	}
}

func BenchmarkBarePacket(b *testing.B) {
	p := gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		b.Fatal(p.ErrorLayer().Error())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		BarePacket(p)
	}
}

func BenchmarkDigestHex(b *testing.B) {
	var (
		p     = gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestHex(hello)
	}
}

func BenchmarkDigest(b *testing.B) {

	var (
		p     = gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Digest(hello)
	}
}

func BenchmarkBare(b *testing.B) {

	var (
		p     = gopacket.NewPacket(tlsPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Bare(hello)
	}
}
