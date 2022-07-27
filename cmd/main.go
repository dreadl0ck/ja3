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

package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket/pcap"
	"os"
)

var (
	flagJSON        = flag.Bool("json", true, "print as JSON array")
	flagCSV         = flag.Bool("csv", false, "print as CSV")
	flagTSV         = flag.Bool("tsv", false, "print as TAB separated values")
	flagSeparator   = flag.String("separator", ",", "set a custom separator")
	flagInput       = flag.String("read", "", "read PCAP file")
	flagDebug       = flag.Bool("debug", false, "toggle debug mode")
	flagInterface   = flag.String("iface", "", "specify network interface to read packets from")
	flagJa3S        = flag.Bool("ja3s", true, "include ja3 server hashes (ja3s)")
	flagOnlyJa3S    = flag.Bool("ja3s-only", false, "dump ja3s only")
	flagSnaplen     = flag.Int("snaplen", 1514, "default snap length for ethernet frames")
	flagPromisc     = flag.Bool("promisc", true, "capture in promiscuous mode (requires root)")
	flagFilter      = flag.String("bpf", "(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && ((tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01) || (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x02))", "BPF filter for pcap, only support on live")
	flagDumpPackets = flag.String("dump", "", "dump pcap file name, only support on live")
	// https://godoc.org/github.com/google/gopacket/pcap#hdr-PCAP_Timeouts
	flagTimeout = flag.Duration("timeout", pcap.BlockForever, "timeout for collecting packet batches")
	flagVersion = flag.Bool("version", false, "display version and exit")
)

const version = "v1.0.2"

func main() {

	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	ja3.Debug = *flagDebug

	if *flagInterface != "" {
		ja3.ReadInterface(*flagInterface, *flagFilter, *flagDumpPackets, os.Stdout, *flagSeparator, *flagJa3S, *flagJSON, *flagSnaplen, *flagPromisc, *flagTimeout)
		return
	}

	if *flagInput == "" {
		fmt.Println("use the -read flag to supply an input file.")
		os.Exit(1)
	}

	if *flagOnlyJa3S {
		ja3.ReadFileJa3s(*flagInput, os.Stdout)
		return
	}

	if *flagTSV {
		ja3.ReadFileCSV(*flagInput, os.Stdout, "\t", *flagJa3S)
		return
	}

	if *flagCSV {
		ja3.ReadFileCSV(*flagInput, os.Stdout, *flagSeparator, *flagJa3S)
		return
	}

	if *flagJSON {
		ja3.ReadFileJSON(*flagInput, os.Stdout, *flagJa3S)
	}
}
