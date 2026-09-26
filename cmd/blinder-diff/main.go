// blinder-diff compares explicitly selected requests in one local manifest.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Splinters-io/blinder/internal/delta"
	"github.com/Splinters-io/blinder/internal/manifest"
)

const maxManifestBytes int64 = 64 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("blinder-diff", flag.ContinueOnError)
	f.SetOutput(io.Discard) // Never echo untrusted arguments or file paths.
	path := f.String("manifest", "", "local manifest file")
	baseline := f.String("baseline", "", "comma-separated baseline request IDs")
	test := f.String("test", "", "comma-separated test request IDs")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: blinder-diff -manifest <file> -baseline <id[,id]> -test <id[,id]>")
			fmt.Fprintln(stdout, "Read-only comparison of explicit observations from one session. No requests are replayed.")
			return 0
		}
		fmt.Fprintln(stderr, "blinder-diff: invalid arguments; use -help")
		return 2
	}
	if f.NArg() != 0 || *path == "" || *baseline == "" || *test == "" {
		fmt.Fprintln(stderr, "blinder-diff: manifest, baseline and test selections are required")
		return 2
	}
	m, err := readManifest(*path)
	if err != nil {
		fmt.Fprintln(stderr, "blinder-diff: cannot read a valid bounded manifest")
		return 2
	}
	r, err := delta.Compare(m, splitIDs(*baseline), splitIDs(*test))
	if err != nil {
		fmt.Fprintln(stderr, "blinder-diff:", err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(stderr, "blinder-diff: cannot write report")
		return 2
	}
	return 0
}

func splitIDs(s string) []string {
	ids := strings.Split(s, ",")
	for i := range ids {
		ids[i] = strings.TrimSpace(ids[i])
	}
	return ids
}

func readManifest(path string) (manifest.ManifestFile, error) {
	// Reject ordinary FIFO/device inputs before Open, which can otherwise block.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return manifest.ManifestFile{}, errors.New("manifest must be a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest.ManifestFile{}, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return manifest.ManifestFile{}, errors.New("manifest must be a bounded regular file")
	}
	// LimitReader also bounds a regular file that grows after Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil || int64(len(data)) > maxManifestBytes {
		return manifest.ManifestFile{}, errors.New("manifest read failed or exceeded limit")
	}
	var m manifest.ManifestFile
	if err := json.Unmarshal(data, &m); err != nil {
		return manifest.ManifestFile{}, err
	}
	return m, nil
}
