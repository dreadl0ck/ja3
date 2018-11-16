/*
 * JA3 - TLS Client Hello Hash
 * Copyright (c) 2018 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketDigest returns only the Ja3 digest
// if the supplied packet contains a TLS client hello
// otherwise returns an empty string
func PacketDigest(p gopacket.Packet) string {
	h, _ := Packet(p)
	return h
}

// Packet returns the Ja3 digest if the supplied packet contains a TLS client hello
// otherwise returns an empty string
func Packet(p gopacket.Packet) (digest string, bare string) {
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

				// invalid length, this is not handled by the tsx package
				// bail out otherwise there will be a panic
				if len(tcp.LayerPayload()) < 6 {
					return "", ""
				}

				// data packet
				var (
					hello = tlsx.ClientHello{}
					err   = hello.Unmarshall(tcp.LayerPayload())
				)
				if err != nil {
					// fmt.Println(err, p.Dump())
					return "", ""
				}

				// return JA3
				return Hash(&hello)
			}
		}
	}
	return "", ""
}
