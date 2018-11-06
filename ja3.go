/*
 * JA3 - TLS Client Hello Hash
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
// These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.
func JA3(hello *tlsx.ClientHello) string {

	// get version
	version := strconv.FormatUint(uint64(hello.Version), 10)

	// collect cipher suites
	var suites []string
	for _, cs := range hello.CipherSuites {
		suites = append(suites, strconv.Itoa(int(cs)))
	}

	// collect extensions
	var exts []string
	for _, e := range hello.AllExtensions {
		exts = append(exts, strconv.Itoa(int(e)))
	}

	// collect supported groups
	var sPoints, sGroups []string
	for _, e := range hello.SupportedGroups {
		sGroups = append(sGroups, strconv.Itoa(int(e)))
	}

	// collect supported points
	for _, e := range hello.SupportedPoints {
		sPoints = append(sPoints, strconv.Itoa(int(e)))
	}

	// build bare
	bare := strings.Join([]string{
		version,
		strings.Join(suites, "-"),
		strings.Join(exts, "-"),
		strings.Join(sGroups, "-"),
		strings.Join(sPoints, "-"),
	}, ",")

	// fmt.Println("ja3:", bare)

	// produce md5
	var out []byte
	for _, b := range md5.Sum([]byte(bare)) {
		out = append(out, b)
	}

	// return as hex string
	return hex.EncodeToString(out)
}
