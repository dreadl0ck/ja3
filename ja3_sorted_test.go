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
	"testing"

	"github.com/dreadl0ck/tlsx"
)

func TestBareSorted(t *testing.T) {
	tests := []struct {
		name           string
		extensions     []uint16
		expectedOrder  string
		description    string
	}{
		{
			name:           "Randomized extensions test 1",
			extensions:     []uint16{10, 11, 35, 16, 5, 13, 18, 21, 23, 27, 43, 45, 51},
			expectedOrder:  "5-10-11-13-16-18-21-23-27-35-43-45-51",
			description:    "Extensions should be sorted in ascending order",
		},
		{
			name:           "Randomized extensions test 2",
			extensions:     []uint16{51, 45, 43, 35, 27, 23, 21, 18, 16, 13, 11, 10, 5},
			expectedOrder:  "5-10-11-13-16-18-21-23-27-35-43-45-51",
			description:    "Same extensions in reverse order should produce same fingerprint",
		},
		{
			name:           "With GREASE values",
			extensions:     []uint16{0x0a0a, 10, 11, 0x1a1a, 35, 16, 5, 0x2a2a},
			expectedOrder:  "5-10-11-16-35",
			description:    "GREASE values should be filtered out",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hello := &tlsx.ClientHelloBasic{
				HandshakeVersion: 771, // TLS 1.2
				CipherSuites:     []tlsx.CipherSuite{49195, 49199, 49196, 49200, 52393, 52392},
				AllExtensions:    tc.extensions,
				SupportedGroups:  []uint16{29, 23, 24},
				SupportedPoints:  []uint8{0},
			}

			// Get the bare string
			bare := BareSorted(hello)
			bareStr := string(bare)

			// Check if extensions are in the expected order
			// The format is: version,ciphers,extensions,groups,points
			// We need to extract the extensions part
			parts := splitBare(bareStr)
			if len(parts) < 3 {
				t.Fatalf("Expected at least 3 parts in bare string, got %d: %s", len(parts), bareStr)
			}

			if parts[2] != tc.expectedOrder {
				t.Errorf("Extensions not in expected order.\nExpected: %s\nGot: %s\nDescription: %s",
					tc.expectedOrder, parts[2], tc.description)
			}
		})
	}
}

func TestBareSortedConsistency(t *testing.T) {
	// Test that the same extensions in different orders produce the same fingerprint
	extensions1 := []uint16{10, 11, 35, 16, 5, 13, 18, 21, 23, 27, 43, 45, 51}
	extensions2 := []uint16{51, 45, 43, 35, 27, 23, 21, 18, 16, 13, 11, 10, 5}

	hello1 := &tlsx.ClientHelloBasic{
		HandshakeVersion: 771,
		CipherSuites:     []tlsx.CipherSuite{49195, 49199, 49196, 49200, 52393, 52392},
		AllExtensions:    extensions1,
		SupportedGroups:  []uint16{29, 23, 24},
		SupportedPoints:  []uint8{0},
	}

	hello2 := &tlsx.ClientHelloBasic{
		HandshakeVersion: 771,
		CipherSuites:     []tlsx.CipherSuite{49195, 49199, 49196, 49200, 52393, 52392},
		AllExtensions:    extensions2,
		SupportedGroups:  []uint16{29, 23, 24},
		SupportedPoints:  []uint8{0},
	}

	digest1 := DigestHexSorted(hello1)
	digest2 := DigestHexSorted(hello2)

	if digest1 != digest2 {
		t.Errorf("Different extension orders produced different digests:\n%s\n%s", digest1, digest2)
	}
}

func TestBareVsBareSorted(t *testing.T) {
	// Test that regular Bare and BareSorted produce different results for randomized extensions
	extensions := []uint16{51, 45, 43, 35, 27, 23, 21, 18, 16, 13, 11, 10, 5}

	hello := &tlsx.ClientHelloBasic{
		HandshakeVersion: 771,
		CipherSuites:     []tlsx.CipherSuite{49195, 49199, 49196, 49200, 52393, 52392},
		AllExtensions:    extensions,
		SupportedGroups:  []uint16{29, 23, 24},
		SupportedPoints:  []uint8{0},
	}

	digestRegular := DigestHex(hello)
	digestSorted := DigestHexSorted(hello)

	if digestRegular == digestSorted {
		t.Errorf("Regular and sorted digests should be different for non-sorted extensions")
	}
}

// Helper function to split the bare string into its components
func splitBare(bare string) []string {
	var parts []string
	var current string
	for _, ch := range bare {
		if ch == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}