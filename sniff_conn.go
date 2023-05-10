package quicsni

import (
	"io"
	"net"
)

type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)  { return conn.r.Read(p) }
func (conn readOnlyConn) Write(_ []byte) (int, error) { return 0, io.EOF }
