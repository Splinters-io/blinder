package rewriter

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// Decoding is deliberately bounded separately from the HTTP body budget: a
// small compressed image can require much more memory than its source bytes.
const (
	maxImageDimension = 16384
	maxImagePixels    = 16 << 20
	maxImageFrames    = 256
)

// rewriteImageDataURL applies the same masking to embedded raster bytes. An
// invalid data URL stays an invalid image, and never becomes an outbound URL.
func rewriteImageDataURL(value string, gate *scrub.Gate) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 5 || !strings.EqualFold(trimmed[:5], "data:") {
		return "", false
	}
	header, payload, ok := strings.Cut(trimmed[5:], ",")
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(header, ";", 2)[0]))
	if !strings.HasPrefix(mediaType, "image/") {
		return "", false
	}
	// Media types are attacker-controlled text too. Only fixed standard
	// spellings can be retained in a newly emitted URL.
	switch mediaType {
	case "image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/webp", "image/avif", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon", "image/apng", "image/tiff":
	default:
		mediaType = "application/octet-stream"
	}
	invalid := "data:" + mediaType + ";base64,"
	if !ok {
		return invalid, true
	}
	decoded, err := url.PathUnescape(payload)
	if err != nil {
		return invalid, true
	}
	body := []byte(decoded)
	parts := strings.Split(header, ";")
	if len(parts) > 1 && strings.EqualFold(strings.TrimSpace(parts[len(parts)-1]), "base64") {
		body, err = base64.StdEncoding.DecodeString(decoded)
		if err != nil {
			return invalid, true
		}
	}
	if mediaType == "image/svg+xml" {
		body = rewriteSVG(body, gate)
	} else {
		img := rewriteImage(body, gate, "body:image:data")
		body = img.body
		if img.contentType != "" {
			mediaType = img.contentType
		}
	}
	return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body), true
}

type imageResult struct {
	body        []byte
	contentType string // Non-empty when the output format differs from the input.
}

// rewriteImage masks pixels and embedded metadata without turning invalid
// image data into a successful load. JPEG, PNG, GIF and WebP are supported.
// Unsupported binary formats produce a valid PNG at the detected dimensions
// when the raw header can be parsed; otherwise they fail closed.
func rewriteImage(body []byte, gate *scrub.Gate, location string) imageResult {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		if w, h, ok := webpDimensions(body); ok && boundedImageSize(w, h) {
			return rewriteWebP(body, w, h, gate)
		}
		return imageResult{body: failedImageBody(body, gate, location)}
	}
	if !boundedImageSize(cfg.Width, cfg.Height) {
		return imageResult{body: failedImageBody(body, gate, location)}
	}
	tag, _ := hex.DecodeString(gate.ContentTag(body))
	var out bytes.Buffer
	switch format {
	case "gif":
		if !boundedGIF(body) {
			return imageResult{body: failedImageBody(body, gate, location)}
		}
		original, err := gif.DecodeAll(bytes.NewReader(body))
		if err != nil {
			return imageResult{body: failedImageBody(body, gate, location)}
		}
		palette := color.Palette{color.RGBA{tag[0], tag[1], tag[2], 255}}
		masked := &gif.GIF{Delay: original.Delay, LoopCount: original.LoopCount, Disposal: original.Disposal,
			Config: image.Config{ColorModel: palette, Width: cfg.Width, Height: cfg.Height}}
		for _, frame := range original.Image {
			masked.Image = append(masked.Image, image.NewPaletted(frame.Bounds(), palette))
		}
		err = gif.EncodeAll(&out, masked)
		if err != nil {
			return imageResult{body: failedImageBody(body, gate, location)}
		}
	case "png", "jpeg":
		if format == "png" && hasPNGChunk(body, "acTL") {
			return imageResult{body: NullBytes(len(body))}
		}
		if _, _, err = image.Decode(bytes.NewReader(body)); err != nil {
			return imageResult{body: failedImageBody(body, gate, location)}
		}
		masked := neutralImage{image.Rect(0, 0, cfg.Width, cfg.Height), color.RGBA{tag[0], tag[1], tag[2], 255}}
		if format == "png" {
			err = png.Encode(&out, masked)
		} else {
			err = jpeg.Encode(&out, masked, &jpeg.Options{Quality: 75})
		}
		if err != nil {
			return imageResult{body: failedImageBody(body, gate, location)}
		}
	default:
		return imageResult{body: failedImageBody(body, gate, location)}
	}
	encoded := out.Bytes()
	if format == "jpeg" {
		encoded = preserveJPEGOrientation(encoded, body)
	}
	return imageResult{body: padImage(encoded, format, len(body), tag)}
}

// rewriteWebP creates a solid-color PNG replacement for a WebP image. Go's
// standard library cannot encode WebP, so the output format changes; the
// caller sets the content-type header accordingly.
func rewriteWebP(body []byte, w, h int, gate *scrub.Gate) imageResult {
	tag, _ := hex.DecodeString(gate.ContentTag(body))
	masked := neutralImage{image.Rect(0, 0, w, h), color.RGBA{tag[0], tag[1], tag[2], 255}}
	var out bytes.Buffer
	if err := png.Encode(&out, masked); err != nil {
		return imageResult{body: NullBytes(len(body))}
	}
	return imageResult{body: padImage(out.Bytes(), "png", len(body), tag), contentType: "image/png"}
}

// webpDimensions extracts canvas width and height from a WebP RIFF container.
// Returns (0, 0, false) for non-WebP or corrupt headers.
func webpDimensions(body []byte) (int, int, bool) {
	if len(body) < 16 || string(body[:4]) != "RIFF" || string(body[8:12]) != "WEBP" {
		return 0, 0, false
	}
	chunk := string(body[12:16])
	switch chunk {
	case "VP8 ":
		// Lossy: 10-byte frame header after the chunk header.
		if len(body) < 30 {
			return 0, 0, false
		}
		chunkLen := int(binary.LittleEndian.Uint32(body[16:20]))
		if chunkLen < 10 || 20+chunkLen > len(body) {
			return 0, 0, false
		}
		data := body[20:]
		if data[3] != 0x9D || data[4] != 0x01 || data[5] != 0x2A {
			return 0, 0, false
		}
		w := int(binary.LittleEndian.Uint16(data[6:8])) & 0x3FFF
		h := int(binary.LittleEndian.Uint16(data[8:10])) & 0x3FFF
		return w, h, w > 0 && h > 0
	case "VP8L":
		// Lossless: 5-byte header after the chunk header.
		if len(body) < 25 {
			return 0, 0, false
		}
		data := body[21:]
		if body[20] != 0x2F {
			return 0, 0, false
		}
		bits := binary.LittleEndian.Uint32(data[:4])
		w := int(bits&0x3FFF) + 1
		h := int((bits>>14)&0x3FFF) + 1
		return w, h, true
	case "VP8X":
		// Extended: explicit canvas size in the VP8X header.
		if len(body) < 30 {
			return 0, 0, false
		}
		w := (int(body[24]) | int(body[25])<<8 | int(body[26])<<16) + 1
		h := (int(body[27]) | int(body[28])<<8 | int(body[29])<<16) + 1
		return w, h, w > 0 && h > 0
	}
	return 0, 0, false
}

func hasPNGChunk(body []byte, kind string) bool {
	for p := 8; p+12 <= len(body); {
		n := int64(binary.BigEndian.Uint32(body[p:]))
		if n > int64(len(body)-p-12) {
			return false
		}
		if string(body[p+4:p+8]) == kind {
			return true
		}
		p += int(n) + 12
	}
	return false
}

// Retain only the technical orientation value, never the original EXIF block
// (which can contain device identity, GPS, comments and a thumbnail).
func preserveJPEGOrientation(encoded, original []byte) []byte {
	for p := 2; p+4 <= len(original); {
		if original[p] != 0xff {
			return encoded
		}
		marker := original[p+1]
		if marker == 0xda || marker == 0xd9 {
			return encoded
		}
		if marker == 0xff {
			p++
			continue
		}
		if marker == 0x01 || marker >= 0xd0 && marker <= 0xd7 {
			p += 2
			continue
		}
		n := int(binary.BigEndian.Uint16(original[p+2:]))
		if n < 2 || n > len(original)-p-2 {
			return encoded
		}
		payload := original[p+4 : p+2+n]
		if marker == 0xe1 && bytes.HasPrefix(payload, []byte("Exif\x00\x00")) {
			orientation := exifOrientation(payload[6:])
			if orientation > 1 {
				// Little-endian TIFF with one SHORT field in IFD0.
				segment := []byte{0xff, 0xe1, 0, 34, 'E', 'x', 'i', 'f', 0, 0,
					'I', 'I', 42, 0, 8, 0, 0, 0, 1, 0, 0x12, 1, 3, 0, 1, 0, 0, 0, orientation, 0, 0, 0, 0, 0, 0, 0}
				result := make([]byte, 0, len(encoded)+len(segment))
				result = append(result, encoded[:2]...)
				result = append(result, segment...)
				return append(result, encoded[2:]...)
			}
		}
		p += n + 2
	}
	return encoded
}

func exifOrientation(tiff []byte) byte {
	if len(tiff) < 8 {
		return 1
	}
	var order binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 1
	}
	if order.Uint16(tiff[2:]) != 42 {
		return 1
	}
	p := int64(order.Uint32(tiff[4:]))
	if p < 8 || p > int64(len(tiff)-2) {
		return 1
	}
	count := int(order.Uint16(tiff[p:]))
	p += 2
	for i := 0; i < count && p+12 <= int64(len(tiff)); i, p = i+1, p+12 {
		entry := tiff[p : p+12]
		if order.Uint16(entry) == 0x112 && order.Uint16(entry[2:]) == 3 && order.Uint32(entry[4:]) == 1 {
			value := order.Uint16(entry[8:])
			if value >= 1 && value <= 8 {
				return byte(value)
			}
		}
	}
	return 1
}

type neutralImage struct {
	rect image.Rectangle
	fill color.RGBA
}

func (n neutralImage) ColorModel() color.Model { return color.RGBAModel }
func (n neutralImage) Bounds() image.Rectangle { return n.rect }
func (n neutralImage) At(x, y int) color.Color { return n.fill }

func boundedImageSize(w, h int) bool {
	return w > 0 && h > 0 && w <= maxImageDimension && h <= maxImageDimension && int64(w)*int64(h) <= maxImagePixels
}

func failedImageBody(body []byte, gate *scrub.Gate, location string) []byte {
	// An upstream error can have an incorrect image Content-Type. Preserve
	// its diagnostic text with normal identity scrubbing, never a valid GIF.
	if utf8.Valid(body) {
		text := true
		for _, r := range string(body) {
			if r < 32 && r != '\n' && r != '\r' && r != '\t' || r == 127 {
				text = false
				break
			}
		}
		if text {
			return gate.ScrubBytes(body, location)
		}
	}
	return NullBytes(len(body))
}

// boundedGIF walks block lengths before DecodeAll allocates frame pixels.
// DecodeAll then validates LZW streams and the rest of the actual format.
func boundedGIF(body []byte) bool {
	if len(body) < 13 || string(body[:6]) != "GIF87a" && string(body[:6]) != "GIF89a" {
		return false
	}
	p := 13
	if body[10]&0x80 != 0 {
		p += 3 << ((body[10] & 7) + 1)
	}
	frames, pixels := 0, int64(0)
	blocks := func() bool {
		for p < len(body) {
			n := int(body[p])
			p++
			if n == 0 {
				return true
			}
			if n > len(body)-p {
				return false
			}
			p += n
		}
		return false
	}
	for p < len(body) {
		kind := body[p]
		p++
		switch kind {
		case 0x3b:
			return frames > 0
		case 0x21:
			if p >= len(body) {
				return false
			}
			p++ // extension label
			if !blocks() {
				return false
			}
		case 0x2c:
			if len(body)-p < 9 {
				return false
			}
			w, h := int(binary.LittleEndian.Uint16(body[p+4:])), int(binary.LittleEndian.Uint16(body[p+6:]))
			if !boundedImageSize(w, h) {
				return false
			}
			pixels += int64(w) * int64(h)
			frames++
			if pixels > maxImagePixels || frames > maxImageFrames {
				return false
			}
			packed := body[p+8]
			p += 9
			if packed&0x80 != 0 {
				p += 3 << ((packed & 7) + 1)
			}
			if p >= len(body) {
				return false
			}
			p++ // minimum LZW code size
			if !blocks() {
				return false
			}
		default:
			return false
		}
	}
	return false
}

// Padding uses format-defined metadata rather than bytes after the end marker.
// Some very small gaps cannot hold a legal chunk/segment; report that real size
// difference instead of damaging the image or retaining original metadata.
func padImage(encoded []byte, format string, size int, tag []byte) []byte {
	gap := size - len(encoded)
	if gap <= 0 {
		return encoded
	}
	var padding []byte
	insert := len(encoded)
	switch format {
	case "png":
		if gap < 12 {
			return encoded
		}
		padding = make([]byte, gap)
		binary.BigEndian.PutUint32(padding, uint32(gap-12))
		copy(padding[4:], "blNd") // private ancillary chunk, safe to copy
		copy(padding[8:gap-4], tag)
		binary.BigEndian.PutUint32(padding[gap-4:], crc32.ChecksumIEEE(padding[4:gap-4]))
		insert -= 12 // IEND
	case "jpeg":
		if gap < 4 {
			return encoded
		}
		padding = make([]byte, 0, gap)
		for left := gap; left > 0; {
			n := min(left, 65537)
			if left-n > 0 && left-n < 4 {
				n -= 4 - (left - n)
			}
			segment := make([]byte, n)
			segment[0], segment[1] = 0xff, 0xfe
			binary.BigEndian.PutUint16(segment[2:], uint16(n-2))
			copy(segment[4:], tag)
			padding = append(padding, segment...)
			left -= n
		}
		insert -= 2 // EOI
	case "gif":
		if gap < 3 || gap == 4 {
			return encoded
		}
		padding = append(make([]byte, 0, gap), 0x21, 0xfe)
		for left := gap - 2; left > 1; {
			n := min(255, left-2)
			if left-n-1 == 2 {
				n--
			}
			padding = append(padding, byte(n))
			data := make([]byte, n)
			copy(data, tag)
			padding = append(padding, data...)
			left -= n + 1
		}
		padding = append(padding, 0)
		insert-- // trailer
	default:
		return encoded
	}
	result := make([]byte, 0, size)
	result = append(result, encoded[:insert]...)
	result = append(result, padding...)
	return append(result, encoded[insert:]...)
}
