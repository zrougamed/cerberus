// Command ouigen builds internal/databases/oui_embedded.tsv.gz, the IEEE
// MAC address registry snapshot compiled into Cerberus, from the public IEEE
// CSV files. Download them first (IEEE rejects some automated clients, so
// this tool reads local files rather than fetching):
//
//	for f in oui/oui.csv oui28/mam.csv oui36/oui36.csv iab/iab.csv; do
//	  curl -sfO "https://standards-oui.ieee.org/$f"
//	done
//	go run ./tools/ouigen -out internal/databases/oui_embedded.tsv.gz \
//	  oui.csv mam.csv oui36.csv iab.csv
//
// Output: gzip of a "# snapshot YYYY-MM-DD entries N" header, then sorted
// "KEY<TAB>Organisation" lines, so regenerating the same input is
// byte-for-byte reproducible.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/zrougamed/cerberus/internal/databases"
)

func main() {
	out := flag.String("out", "internal/databases/oui_embedded.tsv.gz", "output file")
	date := flag.String("date", time.Now().UTC().Format("2006-01-02"), "snapshot date recorded in the header")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("usage: ouigen [-out file] [-date YYYY-MM-DD] oui.csv mam.csv oui36.csv iab.csv")
	}
	if _, err := time.Parse("2006-01-02", *date); err != nil {
		log.Fatalf("bad -date: %v", err)
	}

	merged := map[string]string{}
	for _, path := range flag.Args() {
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		entries, err := databases.ParseIEEERegistryCSV(bufio.NewReader(f))
		_ = f.Close()
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		if len(entries) == 0 {
			log.Fatalf("%s: no registry entries (wrong file?)", path)
		}
		for k, v := range entries {
			merged[k] = cleanName(v)
		}
		fmt.Fprintf(os.Stderr, "%s: %d entries\n", path, len(entries))
	}

	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	zw.ModTime = time.Time{} // reproducible output
	w := bufio.NewWriter(zw)
	fmt.Fprintf(w, "# snapshot %s entries %d\n", *date, len(keys))
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k, merged[k])
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d entries\n", *out, len(keys))
}

// cleanName collapses whitespace and strips tabs/newlines, which would break
// the TSV format.
func cleanName(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
