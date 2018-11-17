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

package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/dreadl0ck/tlsx"
)

const (
	sepValue = "-"
	sepField = ","
)

var (
	sepValueByte = byte(45)
	sepFieldByte = byte(44)
)

// BareToDigestHex converts a bare []byte to a hex string
func BareToDigestHex(bare []byte) string {
	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// Digest returns only the digest md5
func Digest(hello *tlsx.ClientHello) [md5.Size]byte {
	return md5.Sum(Bare(hello))
}

// DigestHex produce md5 hash from bare string
func DigestHex(hello *tlsx.ClientHello) string {
	return BareToDigestHex(Bare(hello))
}

// Bare returns the JA3 bare string for a given tlsx.ClientHello instance
// JA3 is a technique developed by Salesforce, to fingerprint TLS Client Hellos.
// the official python implementation can be found here: https://github.com/salesforce/ja3
// JA3 gathers the decimal values of the bytes for the following fields; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats.
// It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.
// The field order is as follows:
// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Example:
// 769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0
// If there are no SSL Extensions in the Client Hello, the fields are left empty.
// Example:
// 769,4–5–10–9–100–98–3–6–19–18–99,,,
// These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint.
// This is the JA3 SSL Client Fingerprint returned by this function.
func Bare(hello *tlsx.ClientHello) []byte {

	var (
		// TODO use fixed size buffers?
		suites  []byte
		exts    []byte
		sGroups []byte
		sPoints []byte
	)

	// collect cipher suites
	lastElem := len(hello.CipherSuites) - 1
	for i, cs := range hello.CipherSuites {
		suites = strconv.AppendInt(suites, int64(cs), 10)
		if i != lastElem {
			suites = append(suites, sepValueByte)
		}
	}

	// collect extensions
	lastElem = len(hello.AllExtensions) - 1
	for i, e := range hello.AllExtensions {
		exts = strconv.AppendInt(exts, int64(e), 10)
		if i != lastElem {
			exts = append(exts, sepValueByte)
		}
	}

	// collect supported groups
	lastElem = len(hello.SupportedGroups) - 1
	for i, e := range hello.SupportedGroups {
		sGroups = strconv.AppendInt(sGroups, int64(e), 10)
		if i != lastElem {
			sGroups = append(sGroups, sepValueByte)
		}
	}

	// collect supported points
	lastElem = len(hello.SupportedPoints) - 1
	for i, e := range hello.SupportedPoints {
		sPoints = strconv.AppendInt(sPoints, int64(e), 10)
		if i != lastElem {
			sPoints = append(sPoints, sepValueByte)
		}
	}

	// TODO use fixed size buffer?
	// 8 (version) + len(suites) + len(exts) + len(sGroups) + len(sPoints) + 4 (separators)
	// var buf = make([]byte, 8+len(suites)+len(exts)+len(sGroups)+len(sPoints)+4)

	var buf []byte

	// version
	buf = strconv.AppendInt(buf, int64(hello.HandshakeVersion), 10)
	buf = append(buf, sepFieldByte)

	// ciphersuites
	buf = append(buf, suites...)
	buf = append(buf, sepFieldByte)

	// extensions
	buf = append(buf, exts...)
	buf = append(buf, sepFieldByte)

	// groups
	buf = append(buf, sGroups...)
	buf = append(buf, sepFieldByte)

	buf = append(buf, sPoints...)

	return buf
}
