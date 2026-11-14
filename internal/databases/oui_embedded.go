package databases

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"strings"
	"time"
)

// embeddedOUI is the IEEE registry (MA-L, MA-M, MA-S, IAB) compiled into the
// binary so vendors resolve offline from the first start. Regenerate with
// tools/ouigen (see its doc comment); a downloaded cache newer than the
// snapshot is layered on top at runtime.
//
//go:embed oui_embedded.tsv.gz
var embeddedOUI []byte

// parseEmbeddedOUI decodes the snapshot: a "# snapshot YYYY-MM-DD ..." header
// followed by "KEY<TAB>Organisation" lines.
func parseEmbeddedOUI(data []byte) (map[string]string, time.Time, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("embedded OUI snapshot: %w", err)
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var snapshot time.Time
	out := make(map[string]string, 60000)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "# snapshot "); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				snapshot, _ = time.Parse("2006-01-02", f[0])
			}
			continue
		}
		key, name, ok := strings.Cut(line, "\t")
		if !ok || key == "" || name == "" {
			continue
		}
		out[key] = name
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("embedded OUI snapshot: %w", err)
	}
	return out, snapshot, nil
}
