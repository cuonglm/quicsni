package quicsni

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// PaddingFrameType has no semantic value, used to increase
// an Initial packet to the minimum required size.
//
// See: https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames
const PaddingFrameType = 0x00

// CryptoFrameType is used to transmit cryptographic handshake messages.
//
// See: https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames
const CryptoFrameType = 0x6

// A CryptoFrame represents a QUIC CRYPTO frame.
type CryptoFrame struct {
	Offset int64
	Data   []byte
}

// readCryptoFrame reads the data from given bytes stream,
// and return a CryptoFrame if found.
func readCryptoFrame(r *bytes.Reader) (*CryptoFrame, error) {
	frame := &CryptoFrame{}
	offset, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.Offset = int64(offset)
	dataLen, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(r, frame.Data); err != nil {
		return nil, err
	}
	return frame, nil
}
