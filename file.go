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
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dreadl0ck/gopcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadFileCSV reads the PCAP file at the given path
// and prints out all packets containing JA3 digests to the supplied io.Writer
// currently no PCAPNG support
func ReadFileCSV(file string, out io.Writer, separator string) {

	// get PCAP reader
	r, err := gopcap.Open(file)
	if err != nil {
		panic(err)
	}

	// close on exit
	defer r.Close()

	columns := []string{"timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "ja3_digest", "\n"}
	out.Write([]byte(strings.Join(columns, separator)))

	for {
		// read packet data
		h, data, err := r.ReadNextPacket()
		if err == io.EOF {
			return
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
			// get JA3 if possible
			digest, _ = Packet(p)
		)

		// check if we got a result
		if digest != "" {

			var (
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			if tl == nil || nl == nil {
				fmt.Println("error: ", nl, tl, p.Dump())
				continue
			}

			b.WriteString(timeToString(time.Unix(int64(h.TsSec), int64(h.TsUsec*1000))))
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Src().String())
			b.WriteString(separator)
			b.WriteString(nl.NetworkFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(tl.TransportFlow().Dst().String())
			b.WriteString(separator)
			b.WriteString(digest)
			b.WriteString("\n")

			_, err := out.Write([]byte(b.String()))
			if err != nil {
				panic(err)
			}
		}
	}
}
