package rewriter

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var (
	svgWidthRe   = regexp.MustCompile(`(?i)\bwidth\s*=\s*["'](\d+(?:\.\d+)?)(?:px)?["']`)
	svgHeightRe  = regexp.MustCompile(`(?i)\bheight\s*=\s*["'](\d+(?:\.\d+)?)(?:px)?["']`)
	svgViewBoxRe = regexp.MustCompile(`(?i)\bviewBox\s*=\s*["']\s*[\d.]+\s+[\d.]+\s+([\d.]+)\s+([\d.]+)\s*["']`)
)

func rewriteSVG(body []byte, gate *scrub.Gate) []byte {
	w, h := svgDimensions(body)
	tag, _ := hex.DecodeString(gate.ContentTag(body))
	fill := fmt.Sprintf("#%02x%02x%02x", tag[0], tag[1], tag[2])
	return []byte(fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d"><rect width="100%%" height="100%%" fill="%s"/></svg>`,
		w, h, w, h, fill,
	))
}

func svgDimensions(body []byte) (int, int) {
	src := body
	if len(src) > 1024 {
		src = src[:1024]
	}

	var w, h int
	if m := svgWidthRe.FindSubmatch(src); m != nil {
		if v, err := strconv.ParseFloat(string(m[1]), 64); err == nil {
			w = int(v)
		}
	}
	if m := svgHeightRe.FindSubmatch(src); m != nil {
		if v, err := strconv.ParseFloat(string(m[1]), 64); err == nil {
			h = int(v)
		}
	}

	if w == 0 || h == 0 {
		if m := svgViewBoxRe.FindSubmatch(src); m != nil {
			if vw, err := strconv.ParseFloat(string(m[1]), 64); err == nil {
				if vh, err := strconv.ParseFloat(string(m[2]), 64); err == nil {
					if w == 0 {
						w = int(vw)
					}
					if h == 0 {
						h = int(vh)
					}
				}
			}
		}
	}

	if w <= 0 {
		w = 300
	}
	if h <= 0 {
		h = 150
	}
	return w, h
}
