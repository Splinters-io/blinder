package main

import (
	"errors"
	"io/fs"
	"strings"
)

type certificatePlatform struct {
	goos    string
	id      string
	version string
	like    string
}

// Read os-release as data, never as a shell script. The administrator file takes
// precedence over the vendor file; their fields must not be merged.
func detectCertificatePlatform(goos string, readFile func(string) ([]byte, error)) certificatePlatform {
	p := certificatePlatform{goos: goos}
	if goos != "linux" {
		return p
	}
	data, err := readFile("/etc/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		data, err = readFile("/usr/lib/os-release")
	}
	if err != nil {
		return p
	}
	fields := parseOSRelease(string(data))
	p.id, p.version, p.like = fields["ID"], fields["VERSION_ID"], fields["ID_LIKE"]
	return p
}

func parseOSRelease(data string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (key != "ID" && key != "VERSION_ID" && key != "ID_LIKE") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		// These identity fields need only simple identifiers. Reject malformed
		// values, shell substitutions and terminal control characters outright.
		valid := value != ""
		for _, c := range value {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || (key == "ID_LIKE" && c == ' ')) {
				valid = false
				break
			}
		}
		delete(fields, key)
		if valid {
			fields[key] = value
		}
	}
	return fields
}

func (p certificatePlatform) name() string {
	switch p.goos {
	case "darwin":
		return "macOS"
	case "linux":
		switch p.id {
		case "ubuntu", "debian":
			name := "Ubuntu"
			if p.id == "debian" {
				name = "Debian"
			}
			if p.version != "" {
				name += " " + p.version
			}
			return name
		case "":
			return "Linux (distribution unknown)"
		default:
			if p.debianFamily() {
				return "Linux (" + p.id + "; Ubuntu/Debian family)"
			}
			return "Linux (" + p.id + ")"
		}
	case "windows":
		return "Windows"
	default:
		return p.goos
	}
}

func (p certificatePlatform) debianFamily() bool {
	if p.id == "ubuntu" || p.id == "debian" {
		return true
	}
	for _, id := range strings.Fields(p.like) {
		if id == "ubuntu" || id == "debian" {
			return true
		}
	}
	return false
}
