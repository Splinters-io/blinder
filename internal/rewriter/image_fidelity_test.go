package rewriter

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/url"
	"strings"
	"testing"
)

func rasterFixture(t *testing.T, format string) []byte {
	t.Helper()
	pixels := image.NewRGBA(image.Rect(0, 0, 17, 11))
	for y := 0; y < 11; y++ {
		for x := 0; x < 17; x++ {
			pixels.Set(x, y, color.RGBA{uint8(x * 13), uint8(y * 19), uint8(x*y + 17), 255})
		}
	}
	var b bytes.Buffer
	var err error
	switch format {
	case "png":
		err = png.Encode(&b, pixels)
	case "jpeg":
		err = jpeg.Encode(&b, pixels, nil)
	case "gif":
		err = gif.Encode(&b, pixels, nil)
	default:
		t.Fatal("invalid fixture format")
	}
	if err != nil {
		t.Fatal(err)
	}
	// A realistic metadata payload also provides space for legal padding.
	return padImage(b.Bytes(), format, b.Len()+512, []byte("AcmeCorp target.example.com original metadata"))
}

func TestRasterMaskPreservesFormatDimensionsAndSize(t *testing.T) {
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			body := rasterFixture(t, format)
			gate := newTestGate()
			result := RewriteBody(body, "image/"+format, "/photo", gate, true)
			decoded, gotFormat, err := image.Decode(bytes.NewReader(result.Body))
			if err != nil {
				t.Fatalf("masked image failed decoding: %v", err)
			}
			if gotFormat != format || decoded.Bounds() != image.Rect(0, 0, 17, 11) {
				t.Fatalf("lost format/dimensions: %s %v", gotFormat, decoded.Bounds())
			}
			if len(result.Body) != len(body) {
				t.Fatalf("body sizes %d -> %d", len(body), len(result.Body))
			}
			if result.ContentType != "" {
				t.Fatalf("unnecessarily replaced upstream media type: %q", result.ContentType)
			}
			if result.Metadata == nil || result.Metadata.Width != 17 || result.Metadata.Height != 11 {
				t.Fatalf("missing original dimensions: %+v", result.Metadata)
			}
			if bytes.Equal(body, result.Body) || bytes.Contains(result.Body, []byte("AcmeCorp")) || bytes.Contains(result.Body, []byte("target.example.com")) {
				t.Fatal("original pixels or metadata retained")
			}
			// Uniform replacement pixels remove the original graphic.
			for y := 0; y < 11; y++ {
				for x := 0; x < 17; x++ {
					r, g, b, a := decoded.At(x, y).RGBA()
					er, eg, eb, ea := decoded.At(0, 0).RGBA()
					if r != er || g != eg || b != eb || a != ea {
						t.Fatal("original pixel geometry retained")
					}
				}
			}
			if again := RewriteBody(body, "image/"+format, "/photo", gate, true).Body; !bytes.Equal(result.Body, again) {
				t.Fatal("same source became unstable")
			}
			changed := append(append([]byte(nil), body...), []byte("changed-source")...)
			if bytes.Equal(result.Body, RewriteBody(changed, "image/"+format, "/photo", gate, true).Body) {
				t.Fatal("changed source collapsed to same masked bytes")
			}
		})
	}
}

func TestRasterMaskKeepsBrokenResponsesUndecodable(t *testing.T) {
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			full := rasterFixture(t, format)
			// The config/header is intact, but the pixel stream is missing.
			for _, length := range []int{0, 8, 25, 40} {
				body := full[:min(length, len(full))]
				if _, _, err := image.Decode(bytes.NewReader(body)); err == nil {
					continue
				}
				out := RewriteBody(body, "image/"+format, "/broken", newTestGate(), true).Body
				if _, _, err := image.Decode(bytes.NewReader(out)); err == nil {
					t.Fatal("invalid image became a successful load")
				}
				if len(out) != len(body) {
					t.Fatalf("broken binary size changed: %d -> %d", len(body), len(out))
				}
			}
		})
	}
	for _, status := range []int{200, 404, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := []byte("SQLSTATE[42000]: AcmeCorp query failed at target.example.com")
			out := RewriteBody(body, "image/jpeg", "/error", newTestGate(), true, RewriteOpts{StatusCode: status}).Body
			if !bytes.Contains(out, []byte("SQLSTATE[42000]")) || !bytes.Contains(out, []byte("query failed")) || bytes.Contains(out, []byte("AcmeCorp")) || bytes.Contains(out, []byte("target.example.com")) {
				t.Fatalf("diagnostic was lost or leaked identity: %s", out)
			}
			if _, _, err := image.Decode(bytes.NewReader(out)); err == nil {
				t.Fatal("error text became decodable image")
			}
		})
	}
}

func TestRasterMaskPreservesGIFAnimationGeometry(t *testing.T) {
	palette := color.Palette{color.Black, color.White}
	one := image.NewPaletted(image.Rect(0, 0, 17, 11), palette)
	two := image.NewPaletted(image.Rect(3, 4, 8, 9), palette)
	for i := range two.Pix {
		two.Pix[i] = 1
	}
	fixture := &gif.GIF{Image: []*image.Paletted{one, two}, Delay: []int{10, 23}, Disposal: []byte{gif.DisposalNone, gif.DisposalPrevious}, LoopCount: 4,
		Config: image.Config{ColorModel: palette, Width: 17, Height: 11}}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, fixture); err != nil {
		t.Fatal(err)
	}
	got, err := gif.DecodeAll(bytes.NewReader(rewriteImage(b.Bytes(), newTestGate(), "test").body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Image) != 2 || got.LoopCount != 4 || got.Delay[0] != 10 || got.Delay[1] != 23 || got.Disposal[1] != gif.DisposalPrevious || got.Image[1].Bounds() != two.Bounds() {
		t.Fatalf("animation behavior changed: %+v", got)
	}
}

func TestRasterMaskLimitsDecompression(t *testing.T) {
	for _, pair := range [][2]int{{maxImageDimension + 1, 1}, {4097, 4097}, {0, 3}} {
		if boundedImageSize(pair[0], pair[1]) {
			t.Fatalf("accepted invalid dimensions %v", pair)
		}
	}
	oversize := append([]byte(nil), transparentGIF...)
	binary.LittleEndian.PutUint16(oversize[6:8], maxImageDimension+1)
	out := rewriteImage(oversize, newTestGate(), "test").body
	if len(out) != len(oversize) || !bytes.Equal(out, make([]byte, len(out))) {
		t.Fatal("over-budget image was decoded or retained")
	}
	palette := color.Palette{color.Black, color.White}
	animation := &gif.GIF{Config: image.Config{ColorModel: palette, Width: 1, Height: 1}}
	for i := 0; i <= maxImageFrames; i++ {
		animation.Image = append(animation.Image, image.NewPaletted(image.Rect(0, 0, 1, 1), palette))
		animation.Delay = append(animation.Delay, 1)
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, animation); err != nil {
		t.Fatal(err)
	}
	if boundedGIF(b.Bytes()) {
		t.Fatal("GIF exceeded frame budget")
	}
	out = rewriteImage(b.Bytes(), newTestGate(), "test").body
	if _, err := gif.DecodeAll(bytes.NewReader(out)); err == nil {
		t.Fatal("over-budget animation replaced by successful image")
	}
}

func TestRasterPaddingStaysValidAtChunkBoundaries(t *testing.T) {
	for _, format := range []string{"png", "jpeg", "gif"} {
		t.Run(format, func(t *testing.T) {
			body := rasterFixture(t, format)
			gaps := []int{65536, 65537, 65538, 65539, 65540, 131075}
			for n := 0; n < 800; n++ {
				gaps = append(gaps, n)
			}
			for _, gap := range gaps {
				out := padImage(body, format, len(body)+gap, []byte("private-keyed-tag"))
				exact := gap == 0 || format == "png" && gap >= 12 || format == "jpeg" && gap >= 4 || format == "gif" && gap >= 3 && gap != 4
				if exact && len(out) != len(body)+gap {
					t.Fatalf("gap %d: got length %d want %d", gap, len(out), len(body)+gap)
				}
				if _, gotFormat, err := image.Decode(bytes.NewReader(out)); err != nil || gotFormat != format {
					t.Fatalf("gap %d corrupt: %s %v", gap, gotFormat, err)
				}
			}
		})
	}
}

func TestRasterDataURLUsesSameMask(t *testing.T) {
	gate := newTestGate()
	body := rasterFixture(t, "png")
	for _, source := range []string{
		"data:image/png;base64," + base64.StdEncoding.EncodeToString(body),
		"data:image/png," + url.PathEscape(string(body)),
		"data:image/png;base64," + url.PathEscape(base64.StdEncoding.EncodeToString(body)),
	} {
		result, handled := rewriteImageDataURL(source, gate)
		if !handled || result == source {
			t.Fatal("data image not masked")
		}
		_, payload, _ := strings.Cut(result, ",")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		img, _, err := image.Decode(bytes.NewReader(decoded))
		if err != nil || img.Bounds() != image.Rect(0, 0, 17, 11) {
			t.Fatalf("embedded image failed: %v", err)
		}
		if bytes.Contains(decoded, []byte("AcmeCorp")) {
			t.Fatal("embedded image metadata leaked")
		}
	}
	for _, source := range []string{"data:image/png;base64,not%valid!", "data:image/png;base64,not-base64!", "data:image/svg+xml,%3Csvg%3EAcmeCorp%3C/svg%3E", "data:image/AcmeCorp,garbage"} {
		result, handled := rewriteImageDataURL(source, gate)
		if !handled {
			t.Fatal("unsupported embedded image bypassed masking")
		}
		if strings.Contains(strings.ToLower(result), "acmecorp") {
			t.Fatal("image media type leaked identity")
		}
		_, payload, _ := strings.Cut(result, ",")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(decoded, []byte("AcmeCorp")) {
			t.Fatal("unsupported image leaked identity")
		}
		if _, _, err := image.Decode(bytes.NewReader(decoded)); err == nil {
			t.Fatal("invalid data image became valid")
		}
	}
}

func TestRasterJPEGKeepsOnlyEXIFOrientation(t *testing.T) {
	for _, endian := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		body := rasterFixture(t, "jpeg")
		tiff := make([]byte, 26)
		if endian == binary.LittleEndian {
			copy(tiff, "II")
		} else {
			copy(tiff, "MM")
		}
		endian.PutUint16(tiff[2:], 42)
		endian.PutUint32(tiff[4:], 8)
		endian.PutUint16(tiff[8:], 1)
		endian.PutUint16(tiff[10:], 0x112)
		endian.PutUint16(tiff[12:], 3)
		endian.PutUint32(tiff[14:], 1)
		endian.PutUint16(tiff[18:], 6)
		payload := append([]byte("Exif\x00\x00"), tiff...)
		payload = append(payload, []byte("AcmeCorp private device GPS")...)
		segment := []byte{0xff, 0xe1, 0, 0}
		binary.BigEndian.PutUint16(segment[2:], uint16(len(payload)+2))
		segment = append(segment, payload...)
		original := append(append(append([]byte(nil), body[:2]...), segment...), body[2:]...)
		masked := rewriteImage(original, newTestGate(), "test").body
		if bytes.Contains(masked, []byte("private device")) || bytes.Contains(masked, []byte("AcmeCorp")) {
			t.Fatal("EXIF identity retained")
		}
		// Only the rebuilt minimal IFD survives, with the same orientation.
		if len(masked) < 38 || string(masked[6:12]) != "Exif\x00\x00" || binary.LittleEndian.Uint16(masked[30:32]) != 6 {
			t.Fatalf("orientation field missing: %x", masked[:min(len(masked), 38)])
		}
		if _, _, err := image.Decode(bytes.NewReader(masked)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRasterAPNGIsExplicitlyUnsupported(t *testing.T) {
	body := rasterFixture(t, "png")
	chunk := make([]byte, 20)
	binary.BigEndian.PutUint32(chunk, 8)
	copy(chunk[4:], "acTL")
	binary.BigEndian.PutUint32(chunk[8:], 1)
	binary.BigEndian.PutUint32(chunk[16:], crc32.ChecksumIEEE(chunk[4:16]))
	withAnimation := append(append(append([]byte(nil), body[:33]...), chunk...), body[33:]...)
	if !hasPNGChunk(withAnimation, "acTL") {
		t.Fatal("missing animation marker")
	}
	masked := rewriteImage(withAnimation, newTestGate(), "test").body
	if len(masked) != len(withAnimation) || !bytes.Equal(masked, make([]byte, len(masked))) {
		t.Fatal("unsupported animation silently converted to a valid still image")
	}
}

func makeWebPLossy(w, h int) []byte {
	// Minimal lossy WebP: RIFF + VP8 chunk with keyframe header.
	vp8Data := make([]byte, 10)
	vp8Data[3] = 0x9D
	vp8Data[4] = 0x01
	vp8Data[5] = 0x2A
	binary.LittleEndian.PutUint16(vp8Data[6:8], uint16(w))
	binary.LittleEndian.PutUint16(vp8Data[8:10], uint16(h))
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(12+len(vp8Data)))
	buf.Write(size)
	buf.WriteString("WEBPVP8 ")
	binary.LittleEndian.PutUint32(size, uint32(len(vp8Data)))
	buf.Write(size)
	buf.Write(vp8Data)
	return buf.Bytes()
}

func TestWebPDimensions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   []byte
		wantW  int
		wantH  int
		wantOK bool
	}{
		{"lossy_320x240", makeWebPLossy(320, 240), 320, 240, true},
		{"lossy_1x1", makeWebPLossy(1, 1), 1, 1, true},
		{"too_short", []byte("RIFF"), 0, 0, false},
		{"not_webp", []byte("RIFF\x00\x00\x00\x00NOT "), 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, h, ok := webpDimensions(tc.body)
			if ok != tc.wantOK || w != tc.wantW || h != tc.wantH {
				t.Errorf("webpDimensions = (%d, %d, %v), want (%d, %d, %v)", w, h, ok, tc.wantW, tc.wantH, tc.wantOK)
			}
		})
	}
}

func TestWebPRewriteProducesValidPNG(t *testing.T) {
	body := makeWebPLossy(100, 50)
	result := rewriteImage(body, newTestGate(), "test")
	if result.contentType != "image/png" {
		t.Errorf("expected content type image/png, got %q", result.contentType)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(result.body))
	if err != nil {
		t.Fatalf("PNG decode failed: %v", err)
	}
	if cfg.Width != 100 || cfg.Height != 50 {
		t.Errorf("dimensions = %dx%d, want 100x50", cfg.Width, cfg.Height)
	}
}
