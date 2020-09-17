# JA3

[![Go Report Card](https://goreportcard.com/badge/github.com/dreadl0ck/ja3)](https://goreportcard.com/report/github.com/dreadl0ck/ja3)
[![License](https://img.shields.io/badge/License-BSDv3-blue.svg)](https://raw.githubusercontent.com/dreadl0ck/ja3/master/docs/LICENSE)
[![Golang](https://img.shields.io/badge/Go-1.10-blue.svg)](https://golang.org)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-green.svg)
![Windows](https://img.shields.io/badge/Supports-Windows-green.svg)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/dreadl0ck/ja3)

JA3 is a technique developed by Salesforce, to fingerprint the TLS client and server hellos.

The official python implementation can be found [here](https://github.com/salesforce/ja3).
More details can be found in their blog post: https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41

This package provides a pure golang implementation of both the client and server hash functions,
with unit tests to ensure correct behavior and performance. 
This implementation uses [dreadl0ck/gopacket](https://github.com/dreadl0ck/gopacket) for packet decoding.

The **[bradleyfalzon/tlsx](github.com/bradleyfalzon/tlsx)** fork used for parsing the TLS handshakes (**[dreadl0ck/tlsx](github.com/dreadl0ck/tlsx)**),
has been extended to support extracting the server hello message, unit tests, 
benchmarks and a faster decoding interface for use with Ja3 fingerprinting.

Assembly of the ja3 bare was previously implemented with the golang 1.10 **strings.Builder** type,
however using byte slices for this turned out to be faster and causes less allocations. (Thanks for the tips @lukechampine)
Thanks to @guigzzz for his pull request on further reducing allocations!

## Package Usage

This package exports the following API:

Live Capture from interface, outputs CSV with configurable separator or JSON:

```go
func ReadInterface(iface string, out io.Writer, separator string, ja3s bool, asJSON bool, snaplen int, promisc bool, timeout time.Duration) {
```

Files:

```go
func ReadFileJSON(file string, out io.Writer, doJA3s bool)
```
```go
func ReadFileCSV(file string, out io.Writer, separator string, doJA3s bool)
```

Read file and only print Ja3s values, mimics the python implementation from salesforce:

```go
func ReadFileJa3s(file string, out io.Writer)
```

Using gopacket.Packet:

```go
func BarePacket(p gopacket.Packet) []byte
```
```go
func BarePacketJa3s(p gopacket.Packet) []byte
```
```go
func DigestPacket(p gopacket.Packet) [md5.Size]byte
```
```go
func DigestPacketJa3s(p gopacket.Packet) [md5.Size]byte 
```

```go
func DigestHexPacket(p gopacket.Packet) string
```
```go
func DigestHexPacketJa3s(p gopacket.Packet) string 
```

Using tlsx.ClientHello:

```go
func Bare(hello *tlsx.ClientHello) []byte
```
```go
func BareJa3s(hello *tlsx.ServerHello) []byte
```
```go
func Digest(hello *tlsx.ClientHello) [md5.Size]byte
```
```go
func DigestJa3s(hello *tlsx.ServerHello) [md5.Size]byte
```
```go
func DigestHex(hello *tlsx.ClientHello) string
```
```go
func DigestHexJa3s(hello *tlsx.ServerHello) string
```

## Commandline Tool

The commandline program mimics the python reference implementation by default.
It reads the pcap file and prints the all extracted client hellos as JSON array to stdout.
Printing output as CSV, tab separated values or with a custom separator is also supported.

    $ goja3 -h
    Usage of goja3:
      -csv
        	print as CSV
      -debug
        	toggle debug mode
      -iface string
        	specify network interface to read packets from
      -ja3s
        	dump ja3s only
      -json
        	print as JSON array (default true)
      -read string
        	read PCAP file
      -separator string
        	set a custom separator (default ",")
      -tsv
        	print as TAB separated values

Benchmark of the python reference implementation VS this one,
on a 109 MB PCAP dumpfile (DEF CON 23 ICS Village.pcap).
This dump file is interesting for comparison because it contains handshakes without extensions set,
as well as TLS traffic over non standard ports.

Python implementation:

    # https://github.com/salesforce/ja3
    $ time ja3 -a DEF\ CON\ 23\ ICS\ Village.pcap &> /dev/null
    
    real	0m29.031s
    user	0m28.803s
    sys	0m0.141s

Go implementation:

    # github.com/dreadl0ck/ja3
    # disable server fingerprint generation to mimic the behavior of the reference implementation
    $ time goja3 -ja3s=false -json -read DEF\ CON\ 23\ ICS\ Village.pcap &> /dev/null
    
    real	0m0.996s
    user	0m2.245s
    sys	0m0.166s

Output:

    [
        ...
        {
            "destination_ip": "192.168.0.60",
            "destination_port": 443,
            "ja3": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49170-49160-19-49175-49165-49155-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-13-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2",
            "ja3_digest": "e3bb8f1cd407701c585e7a84e96c24e1",
            "ja3s": "",
            "ja3s_digest": "",
            "source_ip": "192.168.0.112",
            "source_port": 59935,
            "timestamp": "1438978270.855224"
        },
        {
            "destination_ip": "192.168.0.30",
            "destination_port": 443,
            "ja3": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49170-49160-19-49175-49165-49155-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-13-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2",
            "ja3_digest": "e3bb8f1cd407701c585e7a84e96c24e1",
            "ja3s": "",
            "ja3s_digest": "",
            "source_ip": "192.168.0.112",
            "source_port": 42455,
            "timestamp": "1438978270.855228"
        }
    ]

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

## JA3S Details

JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients. 

JA3S uses the following field order:
```
SSLVersion,Cipher,SSLExtension
```
With JA3S it is possible to fingerprint the entire cryptographic negotiation between client and it's server by combining JA3 + JA3S. That is because servers will respond to different clients differently but will always respond to the same client the same.

For the Trickbot example:
```
JA3 = 6734f37431670b3ab4292b8f60f29984 ( Fingerprint of Trickbot )
JA3S = 623de93db17d313345d7ea481e7443cf ( Fingerprint of Command and Control Server Response )
```
For the Emotet example:
```
JA3 = 4d7a28d6f2263ed61de88ca66eb011e3 ( Fingerprint of Emotet )
JA3S = 80b3a14bccc8598a1f3bbe83e71f735f ( Fingerprint of Command and Control Server Response )
```

In these malware examples, the command and control server always responds to the malware client in exactly the same way, it does not deviate. So even though the traffic is encrypted and one may not know the command and control server's IPs or domains as they are constantly changing, we can still identify, with reasonable confidence, the malicious communication by fingerprinting the TLS negotiation between client and server. Again, please be aware that these are examples, not indicative of all versions ever, and are intended to illustrate what is possible.

## Benchmarks & Tests

Run the benchmarks and the correctness test with:

    $ go test -v -bench=.
    === RUN   TestDigestHexCorrect
    --- PASS: TestDigestHexCorrect (0.00s)
    === RUN   TestDigestHexComparePcap
    --- PASS: TestDigestHexComparePcap (0.10s)
    === RUN   TestDigestHexJa3sCorrect
    --- PASS: TestDigestHexJa3sCorrect (0.00s)
    === RUN   TestDigestHexJa3sComparePcap
    --- PASS: TestDigestHexJa3sComparePcap (0.10s)
    goos: darwin
    goarch: amd64
    pkg: github.com/dreadl0ck/ja3
    BenchmarkDigestHexPacket
    BenchmarkDigestHexPacket-12        	  781578	      1499 ns/op	     352 B/op	       9 allocs/op
    BenchmarkDigestPacket
    BenchmarkDigestPacket-12           	  827286	      1406 ns/op	     288 B/op	       7 allocs/op
    BenchmarkBarePacket
    BenchmarkBarePacket-12             	 1000000	      1212 ns/op	     288 B/op	       7 allocs/op
    BenchmarkDigestHex
    BenchmarkDigestHex-12              	  895094	      1278 ns/op	     256 B/op	       3 allocs/op
    BenchmarkDigest
    BenchmarkDigest-12                 	  996800	      1318 ns/op	     192 B/op	       1 allocs/op
    BenchmarkBare
    BenchmarkBare-12                   	 1101476	      1188 ns/op	     192 B/op	       1 allocs/op
    BenchmarkDigestHexPacketJa3s
    BenchmarkDigestHexPacketJa3s-12    	 1654360	       619 ns/op	     120 B/op	       4 allocs/op
    BenchmarkDigestPacketJa3s
    BenchmarkDigestPacketJa3s-12       	 2328241	       513 ns/op	      56 B/op	       2 allocs/op
    BenchmarkBarePacketJa3s
    BenchmarkBarePacketJa3s-12         	 3294260	       387 ns/op	      56 B/op	       2 allocs/op
    BenchmarkDigestHexJa3s
    BenchmarkDigestHexJa3s-12          	 2476090	       464 ns/op	     112 B/op	       3 allocs/op
    BenchmarkDigestJa3s
    BenchmarkDigestJa3s-12             	 3321294	       357 ns/op	      48 B/op	       1 allocs/op
    BenchmarkBareJa3s
    BenchmarkBareJa3s-12               	 4964508	       238 ns/op	      48 B/op	       1 allocs/op
    PASS
    ok  	github.com/dreadl0ck/ja3	18.414s
    
Performance comparison with other implementations:

    # https://github.com/open-ch/ja3
    $ time ja3exporter -pcap DEF\ CON\ 23\ ICS\ Village.pcap &> /dev/null
    
    real	0m0.912s
    user	0m1.979s
    sys	0m0.142s
    
    # github.com/dreadl0ck/ja3
    # disable server fingerprint generation to mimic the behavior of the other implementations
    $ time goja3 -ja3s=false -json -read DEF\ CON\ 23\ ICS\ Village.pcap &> /dev/null
    
    real	0m0.996s
    user	0m2.245s
    sys	0m0.166s
    
    # https://github.com/salesforce/ja3
    $ time ja3 -a DEF\ CON\ 23\ ICS\ Village.pcap &> /dev/null
    
    real	0m29.031s
    user	0m28.803s
    sys	0m0.141s
    
Number of records detected:

    # https://github.com/open-ch/ja3
    $ time ja3exporter -pcap DEF\ CON\ 23\ ICS\ Village.pcap | wc -l
    138
    
    # github.com/dreadl0ck/ja3
    $ goja3 -ja3s=false -json -read DEF\ CON\ 23\ ICS\ Village.pcap | jq '. | length'
    138
    
    # https://github.com/salesforce/ja3
    $ time ja3 -a DEF\ CON\ 23\ ICS\ Village.pcap | jq '. | length'
    138

    # https://github.com/salesforce/ja3
    # without -a flag, only tls traffic over port 443 will be extracted
    $ time ja3 DEF\ CON\ 23\ ICS\ Village.pcap | jq '. | length'
    96
    
## Notes

The ja3_output_testpcap.json file for output comparison in the unit tests
was generated with the python reference implementation using:

    ja3 -a test.pcap > ja3_output_testpcap.json