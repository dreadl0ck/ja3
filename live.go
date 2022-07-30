package ja3

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket/pcapgo"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ReadInterface reads packets from the named interface
// if asJSON is true the results will be dumped as newline separated JSON objects
// otherwise CSV will be printed to the supplied io.Writer.
func ReadInterface(iface, bpfFilter, dumpPkg string, out io.Writer, separator string, ja3s bool, asJSON bool, snaplen int, promisc bool, timeout time.Duration) {
	h, err := pcap.OpenLive(iface, int32(snaplen), promisc, timeout)
	if err != nil {
		panic(err)
	}
	defer h.Close()

	if strings.TrimSpace(bpfFilter) != "" {
		if err := h.SetBPFFilter(bpfFilter); err != nil {
			panic(err)
		}
	}

	var dumpFileHandle *os.File
	var pcapWriter *pcapgo.Writer
	if dumpPkg != "" {
		dumpFileHandle, err = os.OpenFile(dumpPkg, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer dumpFileHandle.Close()
		pcapWriter = pcapgo.NewWriter(dumpFileHandle)
		pcapWriter.WriteFileHeader(uint32(snaplen), h.LinkType())
	}

	if !asJSON {
		columns := []string{"timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "ja3_digest"}

		_, err = out.Write([]byte(strings.Join(columns, separator) + "\n"))
		if err != nil {
			panic(err)
		}
	}

	count := 0
	for {
		// read packet data
		data, ci, err := h.ReadPacketData()
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
			p        = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
			bare     = BarePacket(p)
			isServer bool
		)

		if ja3s && len(bare) == 0 {
			bare = BarePacketJa3s(p)
			isServer = true
		}

		// check if we got a result
		if len(bare) > 0 {
			count++

			if pcapWriter != nil {
				pcapWriter.WritePacket(ci, data)
			}

			var (
				b  strings.Builder
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			// got a bare but no transport or network layer
			if tl == nil || nl == nil {
				if Debug {
					fmt.Println("got a nil layer: ", nl, tl, p.Dump(), string(bare))
				}
				continue
			}

			r := &Record{
				DestinationIP:   nl.NetworkFlow().Dst().String(),
				DestinationPort: int(binary.BigEndian.Uint16(tl.TransportFlow().Dst().Raw())),
				SourceIP:        nl.NetworkFlow().Src().String(),
				SourcePort:      int(binary.BigEndian.Uint16(tl.TransportFlow().Src().Raw())),
				Timestamp:       timeToFloat(ci.Timestamp),
			}

			digest := BareToDigestHex(bare)
			if isServer {
				r.JA3S = string(bare)
				r.JA3SDigest = digest
			} else {
				r.JA3 = string(bare)
				r.JA3Digest = digest
			}

			if asJSON {

				// make it pretty please
				b, err := json.MarshalIndent(r, "", "    ")
				if err != nil {
					panic(err)
				}

				if string(b) != "null" { // no matches will result in "null" json
					// write to output io.Writer
					_, err = out.Write(b)
					if err != nil {
						panic(err)
					}

					_, err = out.Write([]byte("\n"))
					if err != nil {
						panic(err)
					}
				}
			} else { // CSV
				b.WriteString(timeToString(ci.Timestamp))
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
}
