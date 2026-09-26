package ws

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
	"unicode/utf8"
)

// Extensions are not negotiated, so RSV bits must be zero. Validate peer
// framing before allocating or interpreting any payload.
func readFrame(src *bufio.Reader, serverToClient bool) (byte, []byte, bool) {
	var header [2]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return 0, nil, false
	}
	first := header[0]
	opcode := first & 0xf
	masked := header[1]&maskBit != 0
	if first&0x70 != 0 || masked == serverToClient {
		return 0, nil, false
	}
	switch opcode {
	case 0, opcodeText, opcodeBin, opcodeClose, opcodePing, opcodePong:
	default:
		return 0, nil, false
	}
	control := opcode >= 8
	length := uint64(header[1] & 0x7f)
	if control && (first&finBit == 0 || length > 125) {
		return 0, nil, false
	}
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(src, ext[:]); err != nil {
			return 0, nil, false
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
		if length < 126 {
			return 0, nil, false
		}
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(src, ext[:]); err != nil {
			return 0, nil, false
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length <= 65535 {
			return 0, nil, false
		}
	}
	if length > maxFrameSize {
		return 0, nil, false
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(src, mask[:]); err != nil {
			return 0, nil, false
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(src, payload); err != nil {
		return 0, nil, false
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if opcode == opcodeClose && !validClosePayload(payload) {
		return 0, nil, false
	}
	return first, payload, true
}

func validClosePayload(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	if len(payload) < 2 || !utf8.Valid(payload[2:]) {
		return false
	}
	code := binary.BigEndian.Uint16(payload[:2])
	return code >= 3000 && code <= 4999 || code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006
}

// relayFrames reports true only after forwarding a valid Close frame. EOF,
// invalid framing and write errors require immediate transport teardown.
func (p *Proxy) relayFrames(src *bufio.Reader, dst net.Conn, serverToClient bool, closing *relayClose) bool {
	var text []byte
	var fragmentedOpcode byte
	for {
		first, payload, ok := readFrame(src, serverToClient)
		if !ok {
			return false
		}
		fin := first&finBit != 0
		opcode := first & 0xf
		if opcode >= 8 {
			if opcode == opcodeClose {
				closing.begin()
			}
			if serverToClient && len(payload) > 0 {
				switch opcode {
				case opcodeClose:
					if len(payload) > 2 {
						reason := []byte(p.gate.Scrub(string(payload[2:]), "ws:close"))
						if len(reason) > 123 {
							reason = reason[:123]
							for !utf8.Valid(reason) {
								reason = reason[:len(reason)-1]
							}
						}
						payload = append(payload[:2:2], reason...)
					}
				case opcodePing, opcodePong:
					if utf8.Valid(payload) {
						payload = p.gate.ScrubBytes(payload, "ws:control")
					}
				}
			}
			if err := p.sendFrame(dst, first, payload, !serverToClient); err != nil {
				return false
			}
			if opcode == opcodeClose {
				return true
			}
			continue
		}
		messageOpcode := opcode
		if opcode == 0 {
			if fragmentedOpcode == 0 {
				return false
			}
			messageOpcode = fragmentedOpcode
		} else {
			// A fragmented message cannot be interrupted by another data message.
			if fragmentedOpcode != 0 {
				return false
			}
			if !fin {
				fragmentedOpcode = opcode
			}
		}
		if messageOpcode == opcodeText {
			if len(text)+len(payload) > maxFrameSize {
				return false
			}
			text = append(text, payload...)
			if fin {
				if !utf8.Valid(text) {
					return false
				}
				// Validate in-flight data while closing, but do not deliver any
				// new application messages while awaiting the Close response.
				if !closing.started() {
					if serverToClient {
						text = p.gate.ScrubBytes(text, "ws:text")
					} else {
						var restoreErr error
						text, restoreErr = p.dealiasText(string(text))
						if restoreErr != nil {
							return false
						}
					}
					if len(text) > maxFrameSize {
						return false
					}
					if !closing.started() {
						if err := p.sendFrame(dst, finBit|opcodeText, text, !serverToClient); err != nil {
							return false
						}
					}
				}
				text = nil
			}
		} else if !closing.started() {
			if err := p.sendFrame(dst, first, payload, !serverToClient); err != nil {
				return false
			}
		}
		if fin {
			fragmentedOpcode = 0
		}
	}
}

func (p *Proxy) sendFrame(dst net.Conn, first byte, payload []byte, mask bool) error {
	if err := dst.SetWriteDeadline(time.Now().Add(p.idleTimeout)); err != nil {
		return err
	}
	return writeFrame(dst, first, payload, mask)
}

func writeFrame(w io.Writer, first byte, payload []byte, mask bool) error {
	frame := []byte{first}
	n := len(payload)
	var length byte
	switch {
	case n <= 125:
		length = byte(n)
	case n <= 65535:
		length = 126
	default:
		length = 127
	}
	if mask {
		length |= maskBit
	}
	frame = append(frame, length)
	if n > 125 && n <= 65535 {
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		frame = append(frame, ext[:]...)
	} else if n > 65535 {
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		frame = append(frame, ext[:]...)
	}
	if mask {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		frame = append(frame, key[:]...)
		for i, b := range payload {
			frame = append(frame, b^key[i%4])
		}
	} else {
		frame = append(frame, payload...)
	}
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}
