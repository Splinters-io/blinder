package main

import (
	"io/fs"
	"reflect"
	"testing"
)

func TestCertificatePlatformDetection(t *testing.T) {
	for _, tc := range []struct {
		name, goos, release, want string
		family                    bool
	}{
		{"mac", "darwin", "ID=ubuntu", "macOS", false},
		{"ubuntu", "linux", "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n", "Ubuntu 24.04", true},
		{"debian", "linux", "ID='debian'\nVERSION_ID='12'", "Debian 12", true},
		{"derivative", "linux", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"", "Linux (linuxmint; Ubuntu/Debian family)", true},
		{"fedora", "linux", "ID=fedora\nID_LIKE=rhel", "Linux (fedora)", false},
		{"unknown", "linux", "# no recognized identity\n", "Linux (distribution unknown)", false},
		{"malformed", "linux", "ID=\"ubuntu\nID_LIKE=notubuntu\n", "Linux (distribution unknown)", false},
		{"untrusted fields", "linux", "ID=$(printf ubuntu)\nID_LIKE=`printf debian`\nVERSION_ID=\"\x1b[31m\"", "Linux (distribution unknown)", false},
		{"windows", "windows", "", "Windows", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			p := detectCertificatePlatform(tc.goos, func(path string) ([]byte, error) {
				calls++
				if path != "/etc/os-release" {
					t.Fatalf("unexpected file: %s", path)
				}
				return []byte(tc.release), nil
			})
			if p.name() != tc.want || p.debianFamily() != tc.family {
				t.Fatalf("detected %q, family=%v; want %q, family=%v", p.name(), p.debianFamily(), tc.want, tc.family)
			}
			if tc.goos != "linux" && calls != 0 {
				t.Fatal("non-Linux detection read Linux release files")
			}
		})
	}
}

func TestOSReleasePrecedenceAndFallback(t *testing.T) {
	for _, tc := range []struct {
		name, etcData, vendorData, want string
		etcErr                          error
		wantPaths                       []string
	}{
		{"fallback", "", "ID=ubuntu\nVERSION_ID=24.04", "Ubuntu 24.04", fs.ErrNotExist, []string{"/etc/os-release", "/usr/lib/os-release"}},
		{"no merging", "ID=ubuntu", "VERSION_ID=99", "Ubuntu", nil, []string{"/etc/os-release"}},
		{"permission failure", "", "ID=ubuntu", "Linux (distribution unknown)", fs.ErrPermission, []string{"/etc/os-release"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			p := detectCertificatePlatform("linux", func(path string) ([]byte, error) {
				paths = append(paths, path)
				if path == "/etc/os-release" {
					return []byte(tc.etcData), tc.etcErr
				}
				return []byte(tc.vendorData), nil
			})
			if p.name() != tc.want || !reflect.DeepEqual(paths, tc.wantPaths) {
				t.Fatalf("got %q from %v; want %q from %v", p.name(), paths, tc.want, tc.wantPaths)
			}
		})
	}
	p := detectCertificatePlatform("linux", func(string) ([]byte, error) { return nil, fs.ErrNotExist })
	if p.name() != "Linux (distribution unknown)" {
		t.Fatalf("missing files: %s", p.name())
	}
}
