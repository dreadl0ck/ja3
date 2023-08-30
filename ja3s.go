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
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/dreadl0ck/tlsx"
)

// BareToDigestHex converts a bare []byte to a hex string.
func BareToDigestHexJa3s(bare []byte) string {
	sum := md5.Sum(bare)
	return hex.EncodeToString(sum[:])
}

// Digest returns only the digest md5.
func DigestJa3s(hello *tlsx.ServerHelloBasic) [md5.Size]byte {
	return md5.Sum(BareJa3s(hello))
}

// DigestHex produce md5 hash from bare string.
func DigestHexJa3s(hello *tlsx.ServerHelloBasic) string {
	return BareToDigestHex(BareJa3s(hello))
}

// BareJa3s returns the JA3S bare string for a given tlsx.ServerHelloBasic instance
// JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients.
// JA3S uses the following field order:
// SSLVersion,Cipher,SSLExtension
func BareJa3s(hello *tlsx.ServerHelloBasic) []byte {

	// TODO: refactor into struct with inbuilt buffer to reduce allocations to ~ zero
	// i.e. only realloc if previously allocated buffer is too small for current packet

	var (
		maxPossibleBufferLength = 5 + 1 + // Version = uint16 => maximum = 65536 = 5chars + 1 field sep
			(5+1)*1 + // CipherSuite = uint16 => maximum = 65536 = 5chars
			(5+1)*len(hello.Extensions) // uint16 = 2B => maximum = 65536 = 5chars

		buffer = make([]byte, 0, maxPossibleBufferLength)
	)

	buffer = strconv.AppendInt(buffer, int64(hello.Vers), 10)
	buffer = append(buffer, sepFieldByte)

	/*
	 *	Cipher Suite
	 */

	buffer = strconv.AppendInt(buffer, int64(hello.CipherSuite), 10)
	buffer = append(buffer, sepFieldByte)

	if len(hello.Extensions) > 0 {

		/*
		 *	Extensions
		 */

		// collect extensions
		lastElem := len(hello.Extensions) - 1
		if len(hello.Extensions) > 1 {
			for _, e := range hello.Extensions[:lastElem] {
				// filter GREASE values
				if !greaseValues[uint16(e)] {
					buffer = strconv.AppendInt(buffer, int64(e), 10)
					buffer = append(buffer, sepValueByte)
				}
			}
		}
		// append last element if extensions are not empty
		if lastElem != -1 {
			// filter GREASE values
			if !greaseValues[uint16(hello.Extensions[lastElem])] {
				buffer = strconv.AppendInt(buffer, int64(hello.Extensions[lastElem]), 10)
			}
		}
		buffer = bytes.TrimSuffix(buffer, []byte{sepValueByte})
	}

	return buffer
}
