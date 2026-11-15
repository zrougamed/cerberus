// advisorygen builds the offline advisory bundle Cerberus matches assets
// against, from a directory of CSAF 2.0 advisories such as CISA's OT feed:
//
//	git clone --depth 1 --filter=blob:none --sparse https://github.com/cisagov/CSAF
//	git -C CSAF sparse-checkout set csaf_files/OT/white
//	go run ./tools/advisorygen -in CSAF/csaf_files/OT/white -out advisories.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zrougamed/cerberus/internal/advisories"
)

func main() {
	in := flag.String("in", "", "directory of CSAF JSON advisories (searched recursively)")
	out := flag.String("out", "advisories.json", "bundle file to write")
	source := flag.String("source", "CISA CSAF OT advisories", "source description stored in the bundle")
	flag.Parse()
	if *in == "" {
		log.Fatal("-in is required")
	}
	b, skipped, err := build(*in, *source, time.Now().UTC())
	if err != nil {
		log.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(*out), data, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s: %d advisories (%d files skipped)\n", *out, len(b.Advisories), skipped)
}

func build(dir, source string, now time.Time) (advisories.Bundle, int, error) {
	b := advisories.Bundle{Format: advisories.BundleFormat, GeneratedAt: now, Source: source}
	root, err := os.OpenRoot(filepath.Clean(dir))
	if err != nil {
		return b, 0, err
	}
	defer root.Close()
	skipped := 0
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, err := root.ReadFile(path)
		if err != nil {
			return err
		}
		a, ok, err := advisories.ParseCSAF(data)
		if err != nil || !ok {
			skipped++
			return nil // feeds include index files and the odd malformed document
		}
		b.Advisories = append(b.Advisories, a)
		return nil
	})
	sort.Slice(b.Advisories, func(i, j int) bool { return b.Advisories[i].ID < b.Advisories[j].ID })
	return b, skipped, err
}
