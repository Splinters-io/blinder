package metadata

import (
	"encoding/binary"
	"testing"
)

func TestExtract_JPEG(t *testing.T) {
	// Minimal JPEG: SOI + APP0 (JFIF) + SOF0 (dimensions) + EOI
	data := buildMinimalJPEG(640, 480)

	result := Extract(data)

	if result.Format != "jpeg" {
		t.Errorf("expected format 'jpeg', got %q", result.Format)
	}
	if result.Width != 640 {
		t.Errorf("expected width 640, got %d", result.Width)
	}
	if result.Height != 480 {
		t.Errorf("expected height 480, got %d", result.Height)
	}
}

func TestExtract_JPEG_Progressive(t *testing.T) {
	data := buildProgressiveJPEG(800, 600)

	result := Extract(data)

	if result.Format != "jpeg" {
		t.Errorf("expected format 'jpeg', got %q", result.Format)
	}
	if !result.Progressive {
		t.Error("expected progressive=true for SOF2 frame")
	}
}

func TestExtract_PNG(t *testing.T) {
	data := buildMinimalPNG(1024, 768, 6) // color type 6 = RGBA

	result := Extract(data)

	if result.Format != "png" {
		t.Errorf("expected format 'png', got %q", result.Format)
	}
	if result.Width != 1024 {
		t.Errorf("expected width 1024, got %d", result.Width)
	}
	if result.Height != 768 {
		t.Errorf("expected height 768, got %d", result.Height)
	}
	if result.ColorType != "rgba" {
		t.Errorf("expected color type 'rgba', got %q", result.ColorType)
	}
}

func TestExtract_GIF(t *testing.T) {
	data := buildMinimalGIF(320, 240)

	result := Extract(data)

	if result.Format != "gif" {
		t.Errorf("expected format 'gif', got %q", result.Format)
	}
	if result.Width != 320 {
		t.Errorf("expected width 320, got %d", result.Width)
	}
	if result.Height != 240 {
		t.Errorf("expected height 240, got %d", result.Height)
	}
}

func TestExtract_WebP(t *testing.T) {
	data := buildMinimalWebP(1920, 1080)

	result := Extract(data)

	if result.Format != "webp" {
		t.Errorf("expected format 'webp', got %q", result.Format)
	}
	if result.Width != 1920 {
		t.Errorf("expected width 1920, got %d", result.Width)
	}
	if result.Height != 1080 {
		t.Errorf("expected height 1080, got %d", result.Height)
	}
}

func TestExtract_BMP(t *testing.T) {
	data := buildMinimalBMP(256, 128)

	result := Extract(data)

	if result.Format != "bmp" {
		t.Errorf("expected format 'bmp', got %q", result.Format)
	}
	if result.Width != 256 {
		t.Errorf("expected width 256, got %d", result.Width)
	}
	if result.Height != 128 {
		t.Errorf("expected height 128, got %d", result.Height)
	}
}

func TestExtract_PDF(t *testing.T) {
	data := buildMinimalPDF("1.7", true, true, false)

	result := Extract(data)

	if result.Format != "pdf" {
		t.Errorf("expected format 'pdf', got %q", result.Format)
	}
	if result.PDFVersion != "1.7" {
		t.Errorf("expected pdf version '1.7', got %q", result.PDFVersion)
	}
	if !result.HasJavaScript {
		t.Error("expected HasJavaScript=true")
	}
	if !result.HasForms {
		t.Error("expected HasForms=true")
	}
}

func TestExtract_PDF_Encrypted(t *testing.T) {
	data := buildMinimalPDF("2.0", false, false, true)

	result := Extract(data)

	if !result.Encrypted {
		t.Error("expected Encrypted=true")
	}
}

func TestExtract_PDF_Identity(t *testing.T) {
	data := []byte("%PDF-1.4\n/Author (John Smith)\n/Title (Secret Report)\n/Producer (LibreOffice 7.6)\n%%EOF")

	result := Extract(data)

	if result.Format != "pdf" {
		t.Errorf("expected format 'pdf', got %q", result.Format)
	}
	if result.Identity.Author != "John Smith" {
		t.Errorf("expected author 'John Smith', got %q", result.Identity.Author)
	}
	if result.Identity.Title != "Secret Report" {
		t.Errorf("expected title 'Secret Report', got %q", result.Identity.Title)
	}
	if result.Producer != "LibreOffice 7.6" {
		t.Errorf("expected producer 'LibreOffice 7.6', got %q", result.Producer)
	}
}

func TestExtract_MP4(t *testing.T) {
	data := buildMinimalMP4("isom")

	result := Extract(data)

	if result.Format != "mp4" {
		t.Errorf("expected format 'mp4', got %q", result.Format)
	}
	if result.FtypBrand != "isom" {
		t.Errorf("expected ftyp brand 'isom', got %q", result.FtypBrand)
	}
}

func TestExtract_MP3(t *testing.T) {
	data := buildMinimalMP3(true)

	result := Extract(data)

	if result.Format != "mp3" {
		t.Errorf("expected format 'mp3', got %q", result.Format)
	}
	if !result.HasID3 {
		t.Error("expected HasID3=true")
	}
}

func TestExtract_MP3_NoID3(t *testing.T) {
	data := buildMinimalMP3(false)

	result := Extract(data)

	if result.Format != "mp3" {
		t.Errorf("expected format 'mp3', got %q", result.Format)
	}
	if result.HasID3 {
		t.Error("expected HasID3=false when no ID3 header")
	}
}

func TestExtract_OOXML_Docx(t *testing.T) {
	data := buildOOXML("word/document.xml", true, false)

	result := Extract(data)

	if result.Format != "docx" {
		t.Errorf("expected format 'docx', got %q", result.Format)
	}
	if !result.HasMacros {
		t.Error("expected HasMacros=true")
	}
}

func TestExtract_OOXML_Xlsx(t *testing.T) {
	data := buildOOXML("xl/workbook.xml", false, false)

	result := Extract(data)

	if result.Format != "xlsx" {
		t.Errorf("expected format 'xlsx', got %q", result.Format)
	}
}

func TestExtract_OOXML_Pptx(t *testing.T) {
	data := buildOOXML("ppt/presentation.xml", false, true)

	result := Extract(data)

	if result.Format != "pptx" {
		t.Errorf("expected format 'pptx', got %q", result.Format)
	}
	if !result.HasActiveX {
		t.Error("expected HasActiveX=true")
	}
}

func TestExtract_WAV(t *testing.T) {
	data := []byte("RIFF\x00\x00\x00\x00WAVE")

	result := Extract(data)

	if result.Format != "wav" {
		t.Errorf("expected format 'wav', got %q", result.Format)
	}
}

func TestExtract_OGG(t *testing.T) {
	data := []byte("OggS\x00\x00\x00\x00")

	result := Extract(data)

	if result.Format != "ogg" {
		t.Errorf("expected format 'ogg', got %q", result.Format)
	}
}

func TestExtract_FLAC(t *testing.T) {
	data := []byte("fLaC\x00\x00\x00\x00")

	result := Extract(data)

	if result.Format != "flac" {
		t.Errorf("expected format 'flac', got %q", result.Format)
	}
}

func TestExtract_MKV(t *testing.T) {
	data := []byte{0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00}

	result := Extract(data)

	if result.Format != "mkv" {
		t.Errorf("expected format 'mkv', got %q", result.Format)
	}
}

func TestExtract_TTF(t *testing.T) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:4], 0x00010000) // TrueType magic

	result := Extract(data)

	if result.Format != "ttf" {
		t.Errorf("expected format 'ttf', got %q", result.Format)
	}
}

func TestExtract_OTF(t *testing.T) {
	data := make([]byte, 16)
	copy(data[0:4], "OTTO")

	result := Extract(data)

	if result.Format != "otf" {
		t.Errorf("expected format 'otf', got %q", result.Format)
	}
}

func TestExtract_WOFF(t *testing.T) {
	data := []byte("wOFF\x00\x00\x00\x00")

	result := Extract(data)

	if result.Format != "woff" {
		t.Errorf("expected format 'woff', got %q", result.Format)
	}
}

func TestExtract_WOFF2(t *testing.T) {
	data := []byte("wOF2\x00\x00\x00\x00")

	result := Extract(data)

	if result.Format != "woff2" {
		t.Errorf("expected format 'woff2', got %q", result.Format)
	}
}

func TestExtract_Unknown(t *testing.T) {
	data := []byte("totally random bytes with no magic")

	result := Extract(data)

	if result.Format != "unknown" {
		t.Errorf("expected format 'unknown', got %q", result.Format)
	}
}

func TestExtract_Empty(t *testing.T) {
	result := Extract(nil)

	if result.Format != "unknown" {
		t.Errorf("expected format 'unknown' for nil input, got %q", result.Format)
	}
}

func TestExtract_TooShort(t *testing.T) {
	result := Extract([]byte{0xFF})

	if result.Format != "unknown" {
		t.Errorf("expected format 'unknown' for 1-byte input, got %q", result.Format)
	}
}

func TestTechnicalJSON(t *testing.T) {
	result := Result{
		Format: "jpeg",
		Width:  640,
		Height: 480,
	}

	j := result.TechnicalJSON()
	if j == "" {
		t.Error("expected non-empty JSON")
	}
	if len(j) > 4096 {
		t.Errorf("technical JSON too long for header: %d bytes", len(j))
	}
}

func TestIdentityFields_NotInTechnical(t *testing.T) {
	result := Result{
		Format: "pdf",
		Identity: IdentityFields{
			Author: "Secret Author",
			Title:  "Secret Title",
		},
	}

	j := result.TechnicalJSON()
	if contains(j, "Secret Author") {
		t.Error("technical JSON must not contain identity author")
	}
	if contains(j, "Secret Title") {
		t.Error("technical JSON must not contain identity title")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Test data builders ---

func buildMinimalJPEG(width, height int) []byte {
	var data []byte
	// SOI
	data = append(data, 0xFF, 0xD8)
	// SOF0 (baseline DCT) - marker, length, precision, height, width, components
	data = append(data, 0xFF, 0xC0)
	sof := make([]byte, 2)
	binary.BigEndian.PutUint16(sof, 11) // length: 8 + 3*1 components
	data = append(data, sof...)
	data = append(data, 8) // precision
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(height))
	data = append(data, h...)
	w := make([]byte, 2)
	binary.BigEndian.PutUint16(w, uint16(width))
	data = append(data, w...)
	data = append(data, 1)          // 1 component
	data = append(data, 1, 0x11, 0) // component: id, sampling, quant table
	// EOI
	data = append(data, 0xFF, 0xD9)
	return data
}

func buildProgressiveJPEG(width, height int) []byte {
	var data []byte
	data = append(data, 0xFF, 0xD8)
	// SOF2 (progressive DCT)
	data = append(data, 0xFF, 0xC2)
	sof := make([]byte, 2)
	binary.BigEndian.PutUint16(sof, 11)
	data = append(data, sof...)
	data = append(data, 8)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(height))
	data = append(data, h...)
	w := make([]byte, 2)
	binary.BigEndian.PutUint16(w, uint16(width))
	data = append(data, w...)
	data = append(data, 1, 1, 0x11, 0)
	data = append(data, 0xFF, 0xD9)
	return data
}

func buildMinimalPNG(width, height int, colorType byte) []byte {
	var data []byte
	// PNG signature
	data = append(data, 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A)
	// IHDR chunk: length(4) + "IHDR" + width(4) + height(4) + bitdepth(1) + colortype(1) + compression(1) + filter(1) + interlace(1) + crc(4)
	ihdr := make([]byte, 4)
	binary.BigEndian.PutUint32(ihdr, 13) // IHDR data length
	data = append(data, ihdr...)
	data = append(data, 'I', 'H', 'D', 'R')
	w := make([]byte, 4)
	binary.BigEndian.PutUint32(w, uint32(width))
	data = append(data, w...)
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(height))
	data = append(data, h...)
	data = append(data, 8)         // bit depth
	data = append(data, colorType) // color type
	data = append(data, 0, 0, 0)   // compression, filter, interlace
	data = append(data, 0, 0, 0, 0) // CRC placeholder
	return data
}

func buildMinimalGIF(width, height int) []byte {
	var data []byte
	data = append(data, 'G', 'I', 'F', '8', '9', 'a')
	// Logical screen descriptor: width(2) + height(2) + packed(1) + bgcolor(1) + aspect(1)
	w := make([]byte, 2)
	binary.LittleEndian.PutUint16(w, uint16(width))
	data = append(data, w...)
	h := make([]byte, 2)
	binary.LittleEndian.PutUint16(h, uint16(height))
	data = append(data, h...)
	data = append(data, 0, 0, 0) // packed, bgcolor, aspect
	return data
}

func buildMinimalWebP(width, height int) []byte {
	var data []byte
	data = append(data, 'R', 'I', 'F', 'F')
	// File size placeholder (4 bytes)
	data = append(data, 0, 0, 0, 0)
	data = append(data, 'W', 'E', 'B', 'P')
	// VP8 chunk (lossy)
	data = append(data, 'V', 'P', '8', ' ')
	// Chunk size (4 bytes) - minimal VP8 bitstream
	chunkSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkSize, 10)
	data = append(data, chunkSize...)
	// VP8 bitstream: frame tag (3 bytes) + start code (3 bytes: 0x9D 0x01 0x2A) + width(2 LE) + height(2 LE)
	data = append(data, 0, 0, 0) // frame tag (keyframe)
	data = append(data, 0x9D, 0x01, 0x2A)
	w := make([]byte, 2)
	binary.LittleEndian.PutUint16(w, uint16(width))
	data = append(data, w...)
	h := make([]byte, 2)
	binary.LittleEndian.PutUint16(h, uint16(height))
	data = append(data, h...)
	return data
}

func buildMinimalBMP(width, height int) []byte {
	var data []byte
	data = append(data, 'B', 'M')
	// File size (4 bytes)
	data = append(data, 0, 0, 0, 0)
	// Reserved (4 bytes)
	data = append(data, 0, 0, 0, 0)
	// Data offset (4 bytes)
	data = append(data, 54, 0, 0, 0)
	// DIB header size (4 bytes) - BITMAPINFOHEADER = 40
	data = append(data, 40, 0, 0, 0)
	// Width (4 bytes, signed LE)
	w := make([]byte, 4)
	binary.LittleEndian.PutUint32(w, uint32(width))
	data = append(data, w...)
	// Height (4 bytes, signed LE)
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, uint32(height))
	data = append(data, h...)
	return data
}

func buildMinimalPDF(version string, hasJS, hasForms, encrypted bool) []byte {
	var data []byte
	data = append(data, []byte("%PDF-"+version+"\n")...)
	if hasJS {
		data = append(data, []byte("/JavaScript (alert)\n")...)
	}
	if hasForms {
		data = append(data, []byte("/AcroForm <<>>\n")...)
	}
	if encrypted {
		data = append(data, []byte("/Encrypt <<>>\n")...)
	}
	data = append(data, []byte("%%EOF")...)
	return data
}

func buildMinimalMP4(brand string) []byte {
	var data []byte
	// ftyp box: size(4) + "ftyp" + brand(4) + version(4)
	boxSize := make([]byte, 4)
	binary.BigEndian.PutUint32(boxSize, 16)
	data = append(data, boxSize...)
	data = append(data, 'f', 't', 'y', 'p')
	if len(brand) >= 4 {
		data = append(data, brand[:4]...)
	} else {
		padded := brand + "    "
		data = append(data, padded[:4]...)
	}
	data = append(data, 0, 0, 0, 0) // version
	return data
}

func buildMinimalMP3(withID3 bool) []byte {
	var data []byte
	if withID3 {
		data = append(data, 'I', 'D', '3')
		data = append(data, 4, 0) // version 2.4
		data = append(data, 0)    // flags
		data = append(data, 0, 0, 0, 0) // size
	}
	// MP3 sync word (0xFFE0 with MPEG1 Layer3 markers)
	data = append(data, 0xFF, 0xFB)
	data = append(data, 0x90, 0x00) // bitrate/sample rate/padding
	return data
}

func buildOOXML(contentPath string, hasMacros, hasActiveX bool) []byte {
	// PK header + content paths as raw bytes (enough for string search detection)
	var data []byte
	data = append(data, 'P', 'K', 0x03, 0x04)
	data = append(data, make([]byte, 26)...) // local file header filler
	data = append(data, []byte(contentPath)...)
	if hasMacros {
		data = append(data, []byte("\x00vbaProject.bin\x00")...)
	}
	if hasActiveX {
		data = append(data, []byte("\x00activeX1.xml\x00")...)
	}
	return data
}
