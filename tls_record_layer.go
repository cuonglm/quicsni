package quicsni

type recordLayer struct {
	ch chan []byte
}

func (r *recordLayer) SetReadKey(_ tlsEncryptionLevel, _ *tlsCipherSuiteTLS13, _ []byte) {
}
func (r *recordLayer) SetWriteKey(_ tlsEncryptionLevel, _ *tlsCipherSuiteTLS13, _ []byte) {
}
func (r *recordLayer) ReadHandshakeMessage() ([]byte, error) { return <-r.ch, nil }
func (r *recordLayer) WriteRecord(b []byte) (int, error)     { r.ch <- b; return len(b), nil }
func (r *recordLayer) SendAlert(uint8)                       {}
