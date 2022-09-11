//go:build !ja3_disable_gopacket

package ja3

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
)

// ReadFileJa3s reads the PCAP file at the given path
// and prints out all packets containing JA3S digests to the supplied io.Writer
func ReadFileJa3s(file string, out io.Writer) {

	r, f, link, err := openPcap(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	count := 0
	for {
		// read packet data
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			if Debug {
				fmt.Println(count, "fingerprints.")
			}
			return
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, link, gopacket.Lazy)
			// get JA3 if possible
			digest = DigestHexPacketJa3s(p)
		)

		// check if we got a result
		if digest != "" {

			count++

			var (
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got an a digest but no transport or network layer
			if tl == nil || nl == nil {
				if Debug {
					fmt.Println("got a nil layer: ", nl, tl, p.Dump(), digest)
				}
				continue
			}

			b.WriteString("[")
			b.WriteString(nl.NetworkFlow().Dst().String())
			b.WriteString(":")
			b.WriteString(tl.TransportFlow().Dst().String())
			b.WriteString("] JA3S: ")
			b.WriteString(string(BarePacketJa3s(p)))
			b.WriteString(" --> ")
			b.WriteString(digest)
			b.WriteString("\n")

			_, err := out.Write([]byte(b.String()))
			if err != nil {
				panic(err)
			}
		}
	}
}
