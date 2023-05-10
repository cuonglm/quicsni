//go:build go1.19 && !go1.20

package quicsni

import (
	"net"

	"github.com/quic-go/qtls-go1-19"
)

type (
	tlsCipherSuiteTLS13 = qtls.CipherSuiteTLS13
	tlsExtraConfig      = qtls.ExtraConfig
	tlsConfig           = qtls.Config
	tlsConn             = qtls.Conn
	tlsEncryptionLevel  = qtls.EncryptionLevel
)

// newTLSServer returns a new TLS server side connection.
func newTLSServer(conn net.Conn, config *tlsConfig, extraConfig *tlsExtraConfig) *tlsConn {
	return qtls.Server(conn, config, extraConfig)
}
