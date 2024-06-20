package quicsni

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
	"src.agwa.name/tlshacks"
)

// ReadClientHello parses the packet and return *tls.ClientHelloInfo if found.
func ReadClientHello(packet []byte) (*tls.ClientHelloInfo, error) {
	hdr, offset, err := ParseInitialHeader(packet)
	if err != nil {
		return nil, err
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, hdr.DestConnectionID, getSalt(hdr.Version))
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "client in", []byte{}, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(clientSecret, hdr.Version)
	if err != nil {
		return nil, fmt.Errorf("NewInitialProtectionKey: %w", err)
	}
	pp := NewPacketProtector(key)
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-client-initial
	//
	// "The unprotected header includes the connection ID and a 4-byte packet number encoding for a packet number of 2"
	unProtectedPayload, err := pp.UnProtect(packet[:offset+hdr.Length], offset, 2)
	if err != nil {
		return nil, err
	}
	cr, err := findCryptoFrame(bytes.NewReader(unProtectedPayload))
	if err != nil {
		return nil, err
	}

	ch := tlshacks.UnmarshalClientHello(cr.Data)
	if ch != nil && ch.Info.ServerName != nil {
		return &tls.ClientHelloInfo{ServerName: *ch.Info.ServerName}, nil
	}
	return nil, errors.New("no client hello found")
}

func findCryptoFrame(br *bytes.Reader) (*CryptoFrame, error) {
	for br.Len() != 0 {
		typ, err := quicvarint.Read(br)
		if err != nil {
			return nil, err
		}
		// Skip padding frames.
		if typ == PaddingFrameType {
			continue
		}
		if typ != CryptoFrameType {
			return nil, errors.New("not CRYPTO FRAME")
		}
		return readCryptoFrame(br)
	}
	return nil, errors.New("no CRYPTO FRAME found")
}
