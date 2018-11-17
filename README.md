# JA3

[![Go Report Card](https://goreportcard.com/badge/github.com/dreadl0ck/ja3)](https://goreportcard.com/report/github.com/dreadl0ck/ja3)
[![License](https://img.shields.io/badge/License-BSDv3-blue.svg)](https://raw.githubusercontent.com/dreadl0ck/ja3/master/docs/LICENSE)
[![Golang](https://img.shields.io/badge/Go-1.10-blue.svg)](https://golang.org)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-green.svg)
![Windows](https://img.shields.io/badge/Supports-Windosa-green.svg)

JA3 is a technique developed by Salesforce, to fingerprint the TLS client hello.

The official python implementation can be found here: https://github.com/salesforce/ja3

More details can be found in their blog post: https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41

This package provides a pure golang implementation, that was created to operate on **ClientHello** instances from the **bradleyfalzon/tlsx** package.
For this to work, the package needed to be slightly modified to store the values for extensions in the order they are encountered.
It was forked to **github.com/dreadl0ck/tlsx**.

This implementation uses the golang 1.10 **strings.Builder** type for faster string concatenation,
and gopacket for packet decoding.

## Package Usage

This package exports the following API:
    
```go
// parse PCAP file from disk and write to out
func ReadFileCSV(file string, out io.Writer, separator string)
func ReadFileJSON(file string, out io.Writer)

// operate on a gopacket.Packet
func PacketDigest(p gopacket.Packet) string
func Packet(p gopacket.Packet) (digest string, bare string)

// operate on a tlsx.ClientHello
func Digest(hello *tlsx.ClientHello) string
func Hash(hello *tlsx.ClientHello) (digest string, bare string)
```

## Commandline Tool

The commandline program mimics the python reference implementation by default, 
reads the pcap file and prints the all extracted client hellos as JSON array to stdout.
Printing output as CSV, tab separated values or with a custom separator is also supported.

    $ goja3 -h
    Usage of goja3:
    -csv
            print as CSV
    -json
            print as JSON array (default true)
    -read string
            read PCAP file
    -separator string
            set a custom separator (default ",")
    -tsv
            print as TAB separated values

Benchmark of the python reference implementation VS this one,
on a 109 MB PCAP dumpfile (DEF CON 23 ICS Village.pcap):

    Python implementation:
    real	0m19.456s
    user	0m18.424s
    sys	0m0.345s

    Go implementation:
    real	0m1.672s
    user	0m2.248s
    sys	0m0.285s

## JA3 Details

JA3 gathers the decimal values of the bytes for the following fields: **SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats**.

It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.

**The field order is as follows:**

    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

**Example:**

    769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0

If there are no SSL Extensions in the Client Hello, the fields are left empty.

**Example:**

    769,4–5–10–9–100–98–3–6–19–18–99,,,

These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint. 

This is the JA3 SSL Client Fingerprint.

JA3 is a much more effective way to detect malicious activity over SSL than IP or domain based IOCs. Since JA3 detects the client application, it doesn’t matter if malware uses DGA (Domain Generation Algorithms), or different IPs for each C2 host, or even if the malware uses Twitter for C2, JA3 can detect the malware itself based on how it communicates rather than what it communicates to.

JA3 is also an excellent detection mechanism in locked-down environments where only a few specific applications are allowed to be installed. In these types of environments one could build a whitelist of expected applications and then alert on any other JA3 hits.

For more details on what you can see and do with JA3 and JA3S, please see this Shmoocon 2018 talk: https://youtu.be/oprPu7UIEuk?t=6m44s

## Benchmarks & Tests

Run the benchmarks and the correctness test with:

    $ go test -bench=. -v
    === RUN   TestDigestCorrect
    --- PASS: TestDigestCorrect (0.00s)
    goos: darwin
    goarch: amd64
    pkg: github.com/dreadl0ck/ja3
    BenchmarkDigestFromPacket-12    	 1000000	      1667 ns/op
    BenchmarkDigestFromHello-12     	 1000000	      1249 ns/op
    PASS
    ok  	github.com/dreadl0ck/ja3	2.969s