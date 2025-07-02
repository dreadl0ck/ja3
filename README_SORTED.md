# JA3 with Sorted TLS Extensions

## Overview

This implementation adds support for normalizing and sorting TLS extensions in the ClientHello when creating JA3 fingerprints. This feature addresses the randomization of TLS extensions introduced by Chrome and other browsers to prevent fingerprinting.

## Background

As described in the article ["Sorting Out Randomized TLS Fingerprints"](https://hnull.org/2022/12/01/sorting-out-randomized-tls-fingerprints/), Chrome and other browsers have started randomizing the order of TLS extensions in the ClientHello message. This randomization causes the same client to produce many different JA3 fingerprints (potentially billions), making the traditional JA3 approach less effective for client identification.

## Solution

By sorting the TLS extensions in lexicographic order before computing the JA3 fingerprint, we can create consistent fingerprints regardless of the randomization. This approach:

1. Maintains fingerprint consistency for clients using extension randomization
2. Preserves the ability to distinguish between different implementations
3. Filters out GREASE values as before
4. Is compatible with existing JA3 infrastructure

## Usage

### Command Line

Use the `-sorted` flag to enable sorted TLS extensions:

```bash
# For PCAP files
goja3 -read file.pcap -json -sorted

# For CSV output
goja3 -read file.pcap -csv -sorted

# For live capture
goja3 -iface eth0 -sorted
```

### Programmatic API

```go
import "github.com/dreadl0ck/ja3"

// For ClientHello structures
hello := &tlsx.ClientHelloBasic{...}
digest := ja3.DigestHexSorted(hello)  // Returns sorted JA3 fingerprint

// For packets
packet := gopacket.Packet{...}
digest := ja3.DigestHexPacketSorted(packet)  // Returns sorted JA3 fingerprint
```

## How It Works

The sorted implementation:

1. Collects all TLS extensions from the ClientHello
2. Filters out GREASE values (0x0a0a, 0x1a1a, etc.)
3. Sorts the remaining extensions in ascending numeric order
4. Constructs the JA3 string with sorted extensions
5. Computes the MD5 hash as usual

## Example

Consider a ClientHello with extensions in randomized order:
- Extensions: [51, 45, 43, 35, 27, 23, 21, 18, 16, 13, 11, 10, 5]

Traditional JA3 would use them in the order presented:
- JA3 string: `771,49195-49199-...,51-45-43-35-27-23-21-18-16-13-11-10-5,...`

Sorted JA3 would reorder them:
- JA3 string: `771,49195-49199-...,5-10-11-13-16-18-21-23-27-35-43-45-51,...`

This ensures that regardless of how Chrome or other browsers randomize the extensions, the fingerprint remains consistent.

## Compatibility

- The sorted mode is optional and backward compatible
- Existing JA3 fingerprints remain unchanged when not using the `-sorted` flag
- JA3S (server fingerprints) are not affected as servers typically don't randomize extensions

## References

- [Sorting Out Randomized TLS Fingerprints](https://hnull.org/2022/12/01/sorting-out-randomized-tls-fingerprints/)
- [Chrome's TLS ClientHello Permutation](https://chromestatus.com/feature/5124606246518784)
- [Original JA3 Repository](https://github.com/salesforce/ja3)