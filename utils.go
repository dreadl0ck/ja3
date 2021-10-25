package ja3

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// PacketSource means we can read Packets.
type PacketSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func openPcap(file string) (PacketSource, *os.File, layers.LinkType, error) {

	// get file handle
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	var (
		reader       PacketSource
		linkType     layers.LinkType
	)

	// try to create pcap reader
	pcapReader, errPcap := pcapgo.NewReader(f)
	if errPcap != nil {

		// maybe its a PCAPNG
		// reopen file, otherwise offsets will be wrong
		err = f.Close()
		if err != nil {
			panic(err)
		}
		f, err = os.Open(file)
		if err != nil {
			panic(err)
		}

		// try to create pcapng reader
		ngReader, errPcapNg := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if errPcapNg != nil {
			// nope
			fmt.Println("pcap error:", errPcap)
			fmt.Println("pcap-ng error:", errPcapNg)
			panic("cannot open PCAP file")
		}

		linkType = ngReader.LinkType()
		reader = ngReader
	} else {
		linkType = pcapReader.LinkType()
		reader = pcapReader
	}

	return reader, f, linkType, err
}
