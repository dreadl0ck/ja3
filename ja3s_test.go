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
	"encoding/hex"
	"io/ioutil"
	"log"
	"testing"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/tlsx"
)

var tlsServerHelloPacket, errDecodeServerHelloPacket = hex.DecodeString("f018982a38be48d343aac4b80800450005b4447b00007906ea20225f7893c0a8b20d01bbefca6011d3eb8013192d801000f087ae00000101080a79facb3a56d9798616030300640200006003035e5bea4420be035069306e15e36eca187d56a201e8e96f0a1afeeb529413fba020746572b9b8832a5b8f236ba51743281c20e923a880067e4c38a754f53f3a8743c02f00001800170000ff01000100000b0002010000100005000302683216030309980b0009940009910004fc308204f8308203e0a00302010202100a86b904765831e240cc6211101f5736300d06092a864886f70d01010b0500305e310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d311d301b0603550403131447656f5472757374205253412043412032303138301e170d3138303130343030303030305a170d3230303730393132303030305a3068310b3009060355040613025553311330110603550408130a43616c69666f726e69613111300f060355040713085061736164656e61311b3019060355040a13124f70656e5820546563686e6f6c6f676965733114301206035504030c0b2a2e6f70656e782e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100bf0efabfe55538e687d4db8f8d615ab1d5dce14702307ca21c0547cd2cc43e455627b4d8decd8015296c19127d29025fbac71f2fc1af1bfe525ed0c2778028a3e7dd643b60842801d9d196651924057827c4d3ce6ae62253b869f384d56a72060055e3537a67a9904e61a4628067f07c680a8bf30c14444d090910c182ea3c5e473b1ab1233838645b0bdfb24265ee32e3521b4bdbae6d79acdbdd7a00c0f00479537079fd352aade5e8394be2f2b397366cfd64bb94b1b96515b4e78d3a2fac04e9d5787792fcf411b6b66cb5dfbc4cb023d93fa99cee630d8ed3558b33e0f2a019ecc5eac16919c48a844f693b5e7ccb4eb84724ab963979c570eb7a3b58ad0203010001a38201a6308201a2301f0603551d230418301680149058ffb09c75a8515477b1edf2a34316389e6cc5301d0603551d0e04160414e03952aaaeb23c67e939ec6022188686bcb314c430210603551d11041a3018820b2a2e6f70656e782e6e657482096f70656e782e6e6574300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302303e0603551d1f043730353033a031a02f862d687474703a2f2f6364702e67656f74727573742e636f6d2f47656f54727573745253414341323031382e63726c304c0603551d2004453043303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c010202307506082b0601050507010104693067302606082b06010505073001861a687474703a2f2f7374617475732e67656f74727573742e636f6d303d06082b060105050730028631687474703a2f2f636163657274732e67656f74727573742e636f6d2f47656f54727573745253414341323031382e63727430090603551d1304023000300d06092a864886f70d01010b0500038201010045a0d33fa95d251c861518096f2ffe89bae2e062cfc4505859b42adeaa775fcf34c2eebde155cfb6449a806abffbaad2e88d77b1397e76ea08265dbc2aa98cb04e3d141c27ed629961d9cd90bb7f6db672408bb15126dd4df4cdf831465c1ee9f321505ace6e7c09d864683fbbaa8ee9fc73e74feefaa5a027067856000f56c9ae39bcb3cc586928429bd8abe5d2a3d8df5c63b4db45fa2cc3ffa6f75b946188019e162fb8dfacf2be3064bf52788378e61c8397ec13e72649fbe15e5c5b6d8bae43ca7b188eda5a41e512f508206fefe96a832ce4676a425ddd06e3cfe93046140818a7359723f2477315f38ab51f83c9dced627efaf6541ed3e9c0767376b200048f3082048b30820373a0")

func getServerHello(p gopacket.Packet, b *testing.B) (hello *tlsx.ServerHelloBasic) {

	if errDecodeServerHelloPacket != nil {
		log.Fatal("failed to decode test packet", errDecodeServerHelloPacket)
	}

	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				b.Fatal("Connection setup")
			} else if tcp.FIN {
				b.Fatal("Connection teardown")
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				b.Fatal("Acknowledgement packet")
			} else if tcp.RST {
				b.Fatal("Unexpected packet")
			} else {
				hello = &tlsx.ServerHelloBasic{}
				err := hello.Unmarshal(tcp.LayerPayload())
				if err != nil {
					b.Fatal("invalid packet", err)
				}
			}
		}
	}
	return
}

/*
 *	Tests
 */

func TestDigestHexJa3sCorrect(t *testing.T) {

	p := gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Lazy)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}

	hash := DigestHexPacketJa3s(p)
	if hash != "5b94af9bf6efc9dea416841602004fbb" {
		t.Fatal(hash, "!=", "5b94af9bf6efc9dea416841602004fbb")
	}
}

func TestDigestHexJa3sComparePcap(t *testing.T) {

	// Step 1: Read output of reference implementation
	data, err := ioutil.ReadFile("ja3s_test.log")
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: generate output wth goja3 and read into buffer
	var (
		b bytes.Buffer
	)

	// read test.pcap and generate fingerprints
	ReadFileJa3s("test.pcap", &b)

	// Step 3: compare the number of fingerprints and then the digest for each record
	if len(data) != len(b.Bytes()) {
		t.Fatal("len(records) != len(referenceRecords): ", len(data), " != ", len(b.Bytes()))
	}

	reference := bytes.Split(data, []byte{'\n'})

	// range reference records
	for i, r := range bytes.Split(b.Bytes(), []byte{'\n'}) {

		// compare reference digest to the one produced by goja3
		if string(r) != string(reference[i]) {
			t.Fatal("message does not match reference implementation: ", string(r), " != ", string(reference[i]))
		}
	}
}

/*
 *	Benchmarks
 */

func BenchmarkDigestHexPacketJa3s(b *testing.B) {

	p := gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Default)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestHexPacketJa3s(p)
	}
}

func BenchmarkDigestPacketJa3s(b *testing.B) {
	p := gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		b.Fatal(p.ErrorLayer().Error())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestPacketJa3s(p)
	}
}

func BenchmarkBarePacketJa3s(b *testing.B) {
	p := gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		b.Fatal(p.ErrorLayer().Error())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		BarePacketJa3s(p)
	}
}

func BenchmarkDigestHexJa3s(b *testing.B) {
	var (
		p     = gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getServerHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestHexJa3s(hello)
	}
}

func BenchmarkDigestJa3s(b *testing.B) {

	var (
		p     = gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getServerHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DigestJa3s(hello)
	}
}

func BenchmarkBareJa3s(b *testing.B) {

	var (
		p     = gopacket.NewPacket(tlsServerHelloPacket, layers.LinkTypeEthernet, gopacket.Lazy)
		hello = getServerHello(p, b)
	)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		BareJa3s(hello)
	}
}
