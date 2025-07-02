//go:build !ja3_disable_gopacket

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
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BarePacket returns the Ja3 digest if the supplied packet contains a TLS client hello
func BarePacket(p gopacket.Packet) []byte {
	return BarePacketWithConfig(p, DefaultConfig)
}

// BarePacketWithConfig returns the Ja3 digest if the supplied packet contains a TLS client hello using the provided config
func BarePacketWithConfig(p gopacket.Packet, config *Config) []byte {
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				// Connection setup
			} else if tcp.FIN {
				// Connection teardown
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				// Acknowledgement packet
			} else if tcp.RST {
				// Unexpected packet
			} else {
				hello := &tlsx.ClientHelloBasic{}
				err := hello.Unmarshal(tcp.LayerPayload())
				if err != nil {
					return nil
				}
				return BareWithConfig(hello, config)
			}
		}
	}
	return nil
}

// BarePacketNormalized returns the Ja3 digest with sort normalization enabled
func BarePacketNormalized(p gopacket.Packet) []byte {
	config := &Config{NormalizeExtensions: true}
	return BarePacketWithConfig(p, config)
}

// DigestPacket returns the Ja3 digest if the supplied packet contains a TLS client hello
func DigestPacket(p gopacket.Packet) [md5.Size]byte {
	return DigestPacketWithConfig(p, DefaultConfig)
}

// DigestPacketWithConfig returns the Ja3 digest if the supplied packet contains a TLS client hello using the provided config
func DigestPacketWithConfig(p gopacket.Packet, config *Config) [md5.Size]byte {
	bare := BarePacketWithConfig(p, config)
	if bare == nil {
		return [md5.Size]byte{}
	}
	return md5.Sum(bare)
}

// DigestPacketNormalized returns the Ja3 digest with sort normalization enabled
func DigestPacketNormalized(p gopacket.Packet) [md5.Size]byte {
	config := &Config{NormalizeExtensions: true}
	return DigestPacketWithConfig(p, config)
}

// DigestHexPacket returns the Ja3 digest as hex string if the supplied packet contains a TLS client hello
func DigestHexPacket(p gopacket.Packet) string {
	return DigestHexPacketWithConfig(p, DefaultConfig)
}

// DigestHexPacketWithConfig returns the Ja3 digest as hex string if the supplied packet contains a TLS client hello using the provided config
func DigestHexPacketWithConfig(p gopacket.Packet, config *Config) string {
	bare := BarePacketWithConfig(p, config)
	if bare == nil {
		return ""
	}
	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// DigestHexPacketNormalized returns the Ja3 digest as hex string with sort normalization enabled
func DigestHexPacketNormalized(p gopacket.Packet) string {
	config := &Config{NormalizeExtensions: true}
	return DigestHexPacketWithConfig(p, config)
}

// DigestPacket returns the Ja3 digest
// for a packet carrying a TLS Server Hello
// or an empty byte slice
func DigestPacketJa3s(p gopacket.Packet) [md5.Size]byte {
	return md5.Sum(BarePacketJa3s(p))
}

// DigestHexPacket returns the hex string for the packet
// for a packet carrying a TLS Client Hello
func DigestHexPacketJa3s(p gopacket.Packet) string {

	bare := BarePacketJa3s(p)
	if len(bare) == 0 {
		return ""
	}

	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// BarePacket returns the Ja3 digest if the supplied packet contains a TLS client hello
// otherwise returns an empty string
func BarePacketJa3s(p gopacket.Packet) []byte {
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				// Connection setup
			} else if tcp.FIN {
				// Connection teardown
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				// Acknowledgement packet
			} else if tcp.RST {
				// Unexpected packet
			} else {
				// data packet
				var (
					hello = tlsx.ServerHelloBasic{}
					err   = hello.Unmarshal(tcp.LayerPayload())
				)
				if err != nil {
					if Debug {
						fmt.Println(err, p.NetworkLayer().NetworkFlow(), p.TransportLayer().TransportFlow())
						//fmt.Println(p.Dump())
					}
					return []byte{}
				}

				// return JA3 bare
				return BareJa3s(&hello)
			}
		}
	}
	return []byte{}
}
