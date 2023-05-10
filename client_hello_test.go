package quicsni

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestReadClientHello(t *testing.T) {
	tests := []struct {
		name       string
		quicConfig *quic.Config
	}{
		{
			"draft29",
			&quic.Config{Versions: []quic.VersionNumber{quic.VersionDraft29}},
		},
		{
			"v1",
			&quic.Config{Versions: []quic.VersionNumber{quic.Version1}},
		},
		{
			"v2",
			&quic.Config{Versions: []quic.VersionNumber{quic.Version2}},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTest(t, tc.quicConfig)
		})
	}
}

func runTest(t *testing.T, quicConfig *quic.Config) {
	t.Helper()
	testHostname := "cuonglm.xyz"

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	defer udpConn.Close()

	go func() {
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quic"},
		}
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			panic(err)
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", udpConn.LocalAddr().String())
		if err != nil {
			panic(err)
		}
		ea, err := quic.Dial(conn, remoteAddr, testHostname, tlsConf, quicConfig)
		if err != nil {
			panic(err)
		}
		s, err := ea.OpenStream()
		if err != nil {
			panic(err)
		}
		s.Close()
	}()

	buf := make([]byte, 1452)
	if _, err := udpConn.Read(buf); err != nil {
		t.Fatal(err)
	}
	clientHello, err := ReadClientHello(buf)
	if err != nil {
		t.Fatal(err)
	}
	if clientHello.ServerName != testHostname {
		t.Errorf("SNI mismatched, got: %q, want: %q", clientHello.ServerName, testHostname)
	}
}
