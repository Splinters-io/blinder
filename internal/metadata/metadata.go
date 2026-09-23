package metadata

import (
	"encoding/binary"
	"encoding/json"
	"strings"
)

type IdentityFields struct {
	Author    string `json:"author,omitempty"`
	Title     string `json:"title,omitempty"`
	Company   string `json:"company,omitempty"`
	Copyright string `json:"copyright,omitempty"`
	GPS       string `json:"gps,omitempty"`
	Camera    string `json:"camera,omitempty"`
}

type Result struct {
	Format      string         `json:"format"`
	Width       int            `json:"width,omitempty"`
	Height      int            `json:"height,omitempty"`
	ColorType   string         `json:"color_type,omitempty"`
	Progressive bool           `json:"progressive,omitempty"`
	PDFVersion  string         `json:"pdf_version,omitempty"`
	Producer    string         `json:"producer,omitempty"`
	HasJavaScript bool         `json:"has_javascript,omitempty"`
	HasForms    bool           `json:"has_forms,omitempty"`
	HasXFA      bool           `json:"has_xfa,omitempty"`
	HasOpenAction bool         `json:"has_open_action,omitempty"`
	Encrypted   bool           `json:"encrypted,omitempty"`
	FtypBrand   string         `json:"ftyp_brand,omitempty"`
	HasID3      bool           `json:"has_id3,omitempty"`
	HasMacros   bool           `json:"has_macros,omitempty"`
	HasActiveX  bool           `json:"has_activex,omitempty"`
	HasOLE      bool           `json:"has_ole,omitempty"`
	ChunkTypes  []string       `json:"chunk_types,omitempty"`
	Identity    IdentityFields `json:"-"`
}

func (r Result) TechnicalJSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"format":"unknown"}`
	}
	return string(b)
}

func Extract(data []byte) Result {
	if len(data) < 2 {
		return Result{Format: "unknown"}
	}

	if data[0] == 0xFF && data[1] == 0xD8 {
		return extractJPEG(data)
	}

	if len(data) >= 8 && string(data[:4]) == "\x89PNG" {
		return extractPNG(data)
	}

	if len(data) >= 6 && (string(data[:6]) == "GIF87a" || string(data[:6]) == "GIF89a") {
		return extractGIF(data)
	}

	if len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return extractWebP(data)
	}

	if len(data) >= 26 && data[0] == 'B' && data[1] == 'M' {
		return extractBMP(data)
	}

	if len(data) >= 5 && string(data[:5]) == "%PDF-" {
		return extractPDF(data)
	}

	if len(data) >= 8 && string(data[4:8]) == "ftyp" {
		return extractMP4(data)
	}

	if len(data) >= 3 && string(data[:3]) == "ID3" {
		return extractMP3(data, true)
	}

	if len(data) >= 2 && data[0] == 0xFF && (data[1]&0xE0) == 0xE0 {
		return extractMP3(data, false)
	}

	// OOXML (.docx/.xlsx/.pptx are ZIP with specific content)
	if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04 {
		return extractOOXML(data)
	}

	// TrueType / OpenType fonts
	if len(data) >= 12 && isSFNT(data) {
		return extractFont(data)
	}

	// WOFF
	if len(data) >= 8 && string(data[:4]) == "wOFF" {
		return Result{Format: "woff"}
	}

	// WOFF2
	if len(data) >= 8 && string(data[:4]) == "wOF2" {
		return Result{Format: "woff2"}
	}

	// WAV (RIFF...WAVE)
	if len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WAVE" {
		return Result{Format: "wav"}
	}

	// OGG
	if len(data) >= 4 && string(data[:4]) == "OggS" {
		return Result{Format: "ogg"}
	}

	// FLAC
	if len(data) >= 4 && string(data[:4]) == "fLaC" {
		return Result{Format: "flac"}
	}

	// AVI (RIFF...AVI )
	if len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "AVI " {
		return Result{Format: "avi"}
	}

	// MKV/WebM (EBML header)
	if len(data) >= 4 && data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3 {
		return Result{Format: "mkv"}
	}

	return Result{Format: "unknown"}
}

func extractJPEG(data []byte) Result {
	r := Result{Format: "jpeg"}
	i := 2

	for i < len(data)-1 {
		if data[i] != 0xFF {
			i++
			continue
		}

		marker := data[i+1]
		i += 2

		if marker == 0xD9 {
			break
		}

		if marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}

		if i+2 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		if segLen < 2 {
			break
		}

		if marker >= 0xC0 && marker <= 0xC2 {
			if i+2+5 <= len(data) {
				r.Height = int(binary.BigEndian.Uint16(data[i+2+1 : i+2+3]))
				r.Width = int(binary.BigEndian.Uint16(data[i+2+3 : i+2+5]))
			}
			if marker == 0xC2 {
				r.Progressive = true
			}
		}

		i += segLen
	}

	return r
}

func extractPNG(data []byte) Result {
	r := Result{Format: "png"}

	if len(data) < 8+8+13 {
		return r
	}

	ihdrData := data[16:]
	if len(ihdrData) < 13 {
		return r
	}

	r.Width = int(binary.BigEndian.Uint32(ihdrData[0:4]))
	r.Height = int(binary.BigEndian.Uint32(ihdrData[4:8]))

	colorByte := ihdrData[9]
	switch colorByte {
	case 0:
		r.ColorType = "grayscale"
	case 2:
		r.ColorType = "rgb"
	case 3:
		r.ColorType = "palette"
	case 4:
		r.ColorType = "grayscale_alpha"
	case 6:
		r.ColorType = "rgba"
	}

	return r
}

func extractGIF(data []byte) Result {
	r := Result{Format: "gif"}

	if len(data) < 10 {
		return r
	}

	r.Width = int(binary.LittleEndian.Uint16(data[6:8]))
	r.Height = int(binary.LittleEndian.Uint16(data[8:10]))

	return r
}

func extractWebP(data []byte) Result {
	r := Result{Format: "webp"}

	if len(data) < 16 {
		return r
	}

	chunkType := string(data[12:16])

	switch {
	case strings.HasPrefix(chunkType, "VP8 "):
		if len(data) < 30 {
			return r
		}
		vp8Start := 20
		if vp8Start+6 <= len(data) && data[vp8Start+3] == 0x9D && data[vp8Start+4] == 0x01 && data[vp8Start+5] == 0x2A {
			if vp8Start+10 <= len(data) {
				r.Width = int(binary.LittleEndian.Uint16(data[vp8Start+6:vp8Start+8])) & 0x3FFF
				r.Height = int(binary.LittleEndian.Uint16(data[vp8Start+8:vp8Start+10])) & 0x3FFF
			}
		}
	case strings.HasPrefix(chunkType, "VP8L"):
		if len(data) < 25 {
			return r
		}
		vp8lStart := 21
		if vp8lStart+4 <= len(data) {
			bits := binary.LittleEndian.Uint32(data[vp8lStart : vp8lStart+4])
			r.Width = int(bits&0x3FFF) + 1
			r.Height = int((bits>>14)&0x3FFF) + 1
		}
	case strings.HasPrefix(chunkType, "VP8X"):
		if len(data) < 30 {
			return r
		}
		canvasStart := 24
		if canvasStart+6 <= len(data) {
			r.Width = int(data[canvasStart]) | int(data[canvasStart+1])<<8 | int(data[canvasStart+2])<<16 + 1
			r.Height = int(data[canvasStart+3]) | int(data[canvasStart+4])<<8 | int(data[canvasStart+5])<<16 + 1
		}
	}

	return r
}

func extractBMP(data []byte) Result {
	r := Result{Format: "bmp"}

	if len(data) < 26 {
		return r
	}

	r.Width = int(binary.LittleEndian.Uint32(data[18:22]))
	h := int(int32(binary.LittleEndian.Uint32(data[22:26])))
	if h < 0 {
		h = -h
	}
	r.Height = h

	return r
}

func extractPDF(data []byte) Result {
	r := Result{Format: "pdf"}
	text := string(data)

	if idx := strings.Index(text, "%PDF-"); idx >= 0 {
		end := idx + 5
		for end < len(text) && end < idx+12 && text[end] != '\n' && text[end] != '\r' && text[end] != ' ' {
			end++
		}
		r.PDFVersion = text[idx+5 : end]
	}

	if strings.Contains(text, "/JavaScript") {
		r.HasJavaScript = true
	}
	if strings.Contains(text, "/AcroForm") {
		r.HasForms = true
	}
	if strings.Contains(text, "/XFA") {
		r.HasXFA = true
	}
	if strings.Contains(text, "/OpenAction") {
		r.HasOpenAction = true
	}
	if strings.Contains(text, "/Encrypt") {
		r.Encrypted = true
	}

	r.Producer = extractPDFField(text, "/Producer")
	r.Identity.Author = extractPDFField(text, "/Author")
	r.Identity.Title = extractPDFField(text, "/Title")
	r.Identity.Company = extractPDFField(text, "/Company")

	return r
}

func extractPDFField(text, key string) string {
	idx := strings.Index(text, key)
	if idx < 0 {
		return ""
	}

	rest := text[idx+len(key):]
	rest = strings.TrimLeft(rest, " ")

	if len(rest) == 0 || rest[0] != '(' {
		return ""
	}

	depth := 0
	start := 1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '(' {
			depth++
		} else if rest[i] == ')' {
			depth--
			if depth == 0 {
				return rest[start:i]
			}
		}
	}

	return ""
}

func extractMP4(data []byte) Result {
	r := Result{Format: "mp4"}

	if len(data) >= 12 {
		r.FtypBrand = strings.TrimSpace(string(data[8:12]))
	}

	return r
}

func extractMP3(data []byte, hasID3 bool) Result {
	r := Result{Format: "mp3"}
	r.HasID3 = hasID3
	return r
}

func extractOOXML(data []byte) Result {
	r := Result{Format: "ooxml"}
	text := string(data)

	if strings.Contains(text, "word/") {
		r.Format = "docx"
	} else if strings.Contains(text, "xl/") {
		r.Format = "xlsx"
	} else if strings.Contains(text, "ppt/") {
		r.Format = "pptx"
	}

	if strings.Contains(text, "vbaProject") {
		r.HasMacros = true
	}
	if strings.Contains(text, "activeX") {
		r.HasActiveX = true
	}
	if strings.Contains(text, "oleObject") {
		r.HasOLE = true
	}

	return r
}

func isSFNT(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[:4])
	return magic == 0x00010000 || // TrueType
		magic == 0x4F54544F // OTTO (OpenType/CFF)
}

func extractFont(data []byte) Result {
	r := Result{Format: "ttf"}
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == 0x4F54544F {
			r.Format = "otf"
		}
	}
	return r
}
