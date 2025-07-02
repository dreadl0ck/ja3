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

// DigestPacket returns the Ja3 digest
// for a packet carrying a TLS Client Hello
// or an empty byte slice
func DigestPacket(p gopacket.Packet) [md5.Size]byte {
	return md5.Sum(BarePacket(p))
}

// DigestPacketSorted returns the Ja3 digest with sorted extensions
// for a packet carrying a TLS Client Hello
// or an empty byte slice. This is resistant to TLS extension randomization.
func DigestPacketSorted(p gopacket.Packet) [md5.Size]byte {
	return md5.Sum(BarePacketSorted(p))
}

// DigestPacket returns the Ja3s digest
// for a packet carrying a TLS Server Hello
// or an empty byte slice
func DigestPacketJa3s(p gopacket.Packet) [md5.Size]byte {
	return md5.Sum(BarePacketJa3s(p))
}

// DigestHexPacket returns the hex string for the packet
// for a packet carrying a TLS Client Hello
func DigestHexPacket(p gopacket.Packet) string {

	bare := BarePacket(p)
	if len(bare) == 0 {
		return ""
	}

	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// DigestHexPacketSorted returns the hex string for the packet with sorted extensions
// for a packet carrying a TLS Client Hello. This is resistant to TLS extension randomization.
func DigestHexPacketSorted(p gopacket.Packet) string {

	bare := BarePacketSorted(p)
	if len(bare) == 0 {
		return ""
	}

	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
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
func BarePacket(p gopacket.Packet) []byte {
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
					hello = tlsx.ClientHelloBasic{}
					err   = hello.Unmarshal(tcp.LayerPayload())
				)
				if err != nil {
					if Debug {
						fmt.Println(err)
						//fmt.Println(p.Dump())
					}
					return []byte{}
				}

				// return JA3 bare
				return Bare(&hello)
			}
		}
	}
	return []byte{}
}

// BarePacketSorted returns the Ja3 digest with sorted extensions if the supplied packet contains a TLS client hello
// otherwise returns an empty string. This is resistant to TLS extension randomization.
func BarePacketSorted(p gopacket.Packet) []byte {
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
					hello = tlsx.ClientHelloBasic{}
					err   = hello.Unmarshal(tcp.LayerPayload())
				)
				if err != nil {
					if Debug {
						fmt.Println(err)
						//fmt.Println(p.Dump())
					}
					return []byte{}
				}

				// return JA3 bare with sorted extensions
				return BareSorted(&hello)
			}
		}
	}
	return []byte{}
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
