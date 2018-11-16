package ja3

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/dreadl0ck/gopcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Record contains all information for a calculated JA3
type Record struct {
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	JA3             string `json:"ja3"`
	JA3Digest       string `json:"ja3_digest"`
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port"`
	Timestamp       string `json:"timestamp"`
}

// ReadFileJSON reads the PCAP file at the given path
// and prints out all packets containing JA3 digests fromatted as JSON to the supplied io.Writer
// currently no PCAPNG support
func ReadFileJSON(file string, out io.Writer) {

	// get PCAP reader
	r, err := gopcap.Open(file)
	if err != nil {
		panic(err)
	}

	// close on exit
	defer r.Close()

	var records []*Record

	for {
		// read packet data
		h, data, err := r.ReadNextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		var (
			// create gopacket
			p = gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)

			// get JA3 if possible
			digest, bare = Packet(p)
		)

		// check if we got a result
		if digest != "" {

			var (
				nl = p.NetworkLayer()
				tl = p.TransportLayer()
			)

			if tl == nil || nl == nil {
				fmt.Println("error: ", nl, tl, p.Dump())
				continue
			}

			srcPort, _ := strconv.Atoi(tl.TransportFlow().Src().String())
			dstPort, _ := strconv.Atoi(tl.TransportFlow().Dst().String())

			records = append(records, &Record{
				DestinationIP:   nl.NetworkFlow().Dst().String(),
				DestinationPort: dstPort,
				JA3:             bare,
				JA3Digest:       digest,
				SourceIP:        nl.NetworkFlow().Src().String(),
				SourcePort:      srcPort,
				Timestamp:       timeToString(time.Unix(int64(h.TsSec), int64(h.TsUsec*1000))),
			})
		}
	}

	b, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		panic(err)
	}

	_, err = out.Write(b)
	if err != nil {
		panic(err)
	}
}

func timeToString(t time.Time) string {
	micro := fmt.Sprintf("%06d", t.Nanosecond()/1000)
	return strconv.FormatInt(t.Unix(), 10) + "." + micro
}
