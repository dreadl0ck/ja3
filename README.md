# JA3

[![Go Report Card](https://goreportcard.com/badge/github.com/dreadl0ck/ja3)](https://goreportcard.com/report/github.com/dreadl0ck/ja3)
[![License](https://img.shields.io/badge/License-BSDv3-blue.svg)](https://raw.githubusercontent.com/dreadl0ck/ja3/master/docs/LICENSE)
[![Golang](https://img.shields.io/badge/Go-1.10-blue.svg)](https://golang.org)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-green.svg)
![Windows](https://img.shields.io/badge/Supports-Windows-green.svg)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/dreadl0ck/ja3)

JA3 is a technique developed by Salesforce, to fingerprint the TLS client hello.

The official python implementation can be found here: https://github.com/salesforce/ja3

More details can be found in their blog post: https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41

This package provides a pure golang implementation, that was created to operate on **ClientHello** instances from the **bradleyfalzon/tlsx** package.
For this to work, the package needed to be slightly modified to store the values for extensions in the order they are encountered.
It was forked to **github.com/dreadl0ck/tlsx**.

This implementation uses gopacket for packet decoding.
Assembly of the ja3 bare was previously implemented with the golang 1.10 **strings.Builder** type,
however using byte slices for this turned out to be faster and causes less allocations. (Thanks for the tips @lukechampine)

Thanks to @guigzzz for his pull request on further reducing allocations!

## Package Usage

This package exports the following API:

Files:

```go
func ReadFileJSON(file string, out io.Writer)
```
```go
func ReadFileCSV(file string, out io.Writer, separator string)
```

Using gopacket.Packet:

```go
func BarePacket(p gopacket.Packet) []byte
```
```go
func DigestPacket(p gopacket.Packet) [md5.Size]byte
```
```go
func DigestHexPacket(p gopacket.Packet) string 
```

Using tlsx.ClientHello:

```go
func Bare(hello *tlsx.ClientHello) []byte
```
```go
func Digest(hello *tlsx.ClientHello) [md5.Size]byte
```
```go
func DigestHex(hello *tlsx.ClientHello) string
```


## Commandline Tool

The commandline program mimics the python reference implementation by default.
It reads the pcap file and prints the all extracted client hellos as JSON array to stdout.
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

    $ time ja3 pcaps/DEF\ CON\ 23\ ICS\ Village.pcap
    real	0m19.456s
    user	0m18.424s
    sys	0m0.345s

    Go implementation:

    $ time goja3 -read pcaps/DEF\ CON\ 23\ ICS\ Village.pcap
    real	0m0.996s
    user	0m1.800s
    sys	0m0.119s

Output:

    [
        ...
        {
            "destination_ip": "192.168.0.60",
            "destination_port": 443,
            "ja3": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49170-49160-19-49175-49165-49155-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-13-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2",
            "ja3_digest": "e3bb8f1cd407701c585e7a84e96c24e1",
            "source_ip": "192.168.0.112",
            "source_port": 59935,
            "timestamp": "1438978270.855224"
        },
        {
            "destination_ip": "192.168.0.30",
            "destination_port": 443,
            "ja3": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49170-49160-19-49175-49165-49155-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-13-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2",
            "ja3_digest": "e3bb8f1cd407701c585e7a84e96c24e1",
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

## Benchmarks & Tests

Run the benchmarks and the correctness test with:

    $ go test -v -bench=.
    === RUN   TestDigestHexCorrect
    --- PASS: TestDigestHexCorrect (0.00s)
    goos: darwin
    goarch: amd64
    pkg: github.com/dreadl0ck/ja3
    BenchmarkDigestHexPacket-12    	 2000000	       927 ns/op	     464 B/op	      13 allocs/op
    BenchmarkDigestPacket-12       	 2000000	       866 ns/op	     400 B/op	      11 allocs/op
    BenchmarkBarePacket-12         	 2000000	       662 ns/op	     400 B/op	      11 allocs/op
    BenchmarkDigestHex-12          	 3000000	       575 ns/op	     256 B/op	       3 allocs/op
    BenchmarkDigest-12             	 3000000	       509 ns/op	     192 B/op	       1 allocs/op
    BenchmarkBare-12               	 5000000	       336 ns/op	     192 B/op	       1 allocs/op
    PASS
    ok  	github.com/dreadl0ck/ja3	13.820s