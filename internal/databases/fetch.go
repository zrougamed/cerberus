package databases

import (
	"fmt"
	"io"
)

// Upper bounds for bodies fetched from remote registries. The IEEE and IANA
// CSVs are a few MB today; the caps leave headroom while keeping a hostile or
// broken mirror from exhausting memory.
const (
	maxRegistryBody = 32 << 20
	maxVendorBody   = 4 << 10
)

// readLimited reads r to EOF, failing instead of truncating when the body is
// larger than limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return body, nil
}
