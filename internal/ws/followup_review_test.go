package ws

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestFollowupFragmentBoundaryPrivacy(t *testing.T) {
	input := append([]byte{0x01, 0x04}, []byte("Acme")...)
	input = append(input, 0x80, 0x04)
	input = append(input, []byte("Corp")...)
	output := reviewRelay(t, input, true)
	reader := bytes.NewReader(output)
	var message strings.Builder
	for reader.Len() > 0 {
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		n := uint64(header[1] & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(reader, ext[:]); err != nil {
				t.Fatal(err)
			}
			n = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(reader, ext[:]); err != nil {
				t.Fatal(err)
			}
			n = binary.BigEndian.Uint64(ext[:])
		}
		if n > uint64(reader.Len()) {
			t.Fatal("invalid output frame length")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		if header[0]&0x0f <= 1 {
			message.Write(body)
		}
	}
	if strings.Contains(message.String(), "AcmeCorp") {
		t.Fatalf("reassembled message exposes configured token: %q", message.String())
	}
}
