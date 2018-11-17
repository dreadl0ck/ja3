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
	"strings"

	"github.com/dreadl0ck/tlsx"
)

const (
	sepValue = "-"
	sepField = ","
)

// Digest returns only the digest md5
func Digest(hello *tlsx.ClientHello) string {
	h, _ := Hash(hello)
	return h
}

// Hash returns the JA3 hash for a given tlsx.ClientHello instance and the bare string used to generate it
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
// This implementation uses multiple strings.Builder instances for performance
func Hash(hello *tlsx.ClientHello) (digest string, bare string) {

	var (
		// get version
		version = strconv.FormatUint(uint64(hello.HandshakeVersion), 10)
		suites  strings.Builder
		exts    strings.Builder
		sGroups strings.Builder
		sPoints strings.Builder
	)

	// collect cipher suites
	lastElem := len(hello.CipherSuites) - 1
	for i, cs := range hello.CipherSuites {
		suites.WriteString(strconv.Itoa(int(cs)))
		if i != lastElem {
			suites.WriteString(sepValue)
		}
	}

	// collect extensions
	lastElem = len(hello.AllExtensions) - 1
	for i, e := range hello.AllExtensions {
		exts.WriteString(strconv.Itoa(int(e)))
		if i != lastElem {
			exts.WriteString(sepValue)
		}
	}

	// collect supported groups
	lastElem = len(hello.SupportedGroups) - 1
	for i, e := range hello.SupportedGroups {
		sGroups.WriteString(strconv.Itoa(int(e)))
		if i != lastElem {
			sGroups.WriteString(sepValue)
		}
	}

	// collect supported points
	lastElem = len(hello.SupportedPoints) - 1
	for i, e := range hello.SupportedPoints {
		sPoints.WriteString(strconv.Itoa(int(e)))
		if i != lastElem {
			sPoints.WriteString(sepValue)
		}
	}

	// create bare string
	var b strings.Builder

	// allocate enough space for all fields + 4 separators
	b.Grow(len(version) + suites.Len() + exts.Len() + sGroups.Len() + sPoints.Len() + 4)

	b.WriteString(version)
	b.WriteString(sepField)
	b.WriteString(suites.String())
	b.WriteString(sepField)
	b.WriteString(exts.String())
	b.WriteString(sepField)
	b.WriteString(sGroups.String())
	b.WriteString(sepField)
	b.WriteString(sPoints.String())

	// apparently the extra step with the sum variable is necessary, instead of doing:
	// return hex.EncodeToString(md5.Sum([]byte(b.String()))[:]), b.String()
	// this produces a compile error: slice of unaddressable value

	// produce md5 hash from bare string
	sum := md5.Sum([]byte(b.String()))

	// return as hex string
	// [:] to create []byte from [Size]byte
	return hex.EncodeToString(sum[:]), b.String()
}
