package advisories

import (
	"strconv"
	"strings"
)

// version is the numeric parts of a version string: "V32.011" -> [32 11],
// "MS_4.1_14142" -> [4 1 14142], "6.3_HF3" -> [6 3 3].
type version []int

// maxVersionParts bounds parsing of odd strings.
const maxVersionParts = 8

func parseVersion(s string) (version, bool) {
	var v version
	n, inNum := 0, false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if n > 1e8 {
				return nil, false // absurd number: not a version
			}
			n = n*10 + int(r-'0')
			inNum = true
			continue
		}
		if inNum {
			v = append(v, n)
			n, inNum = 0, false
			if len(v) == maxVersionParts {
				break
			}
		}
	}
	if inNum && len(v) < maxVersionParts {
		v = append(v, n)
	}
	return v, len(v) > 0
}

// compare returns -1, 0 or 1; missing parts count as zero.
func (a version) compare(b version) int {
	for i := range max(len(a), len(b)) {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

type constraint struct {
	op string // "<", "<=", ">", ">=", "=", "!="
	v  version
}

// versionSet is a parsed affected-version expression.
type versionSet struct {
	all  bool // every version is affected
	ok   bool // parsed; false means "cannot compare"
	cons []constraint
}

// parseVersionSet understands what CSAF advisories use in practice: empty
// or "vers:all/*" (all versions), a bare version (exact), "<6.3.1",
// "vers:scheme/>=2.0|<3.1" (VERS, constraints joined by |, all must hold),
// and "<=9.7".
func parseVersionSet(s string) versionSet {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "vers:"); ok {
		if _, after, found := strings.Cut(rest, "/"); found {
			s = after
		} else {
			return versionSet{}
		}
	}
	if s == "" || s == "*" {
		return versionSet{all: true, ok: true}
	}
	var set versionSet
	for _, part := range strings.Split(s, "|") {
		part = strings.TrimSpace(part)
		op := "="
		for _, candidate := range []string{"<=", ">=", "!=", "<", ">", "="} {
			if strings.HasPrefix(part, candidate) {
				op, part = candidate, strings.TrimSpace(part[len(candidate):])
				break
			}
		}
		v, ok := parseVersion(part)
		if !ok {
			return versionSet{}
		}
		set.cons = append(set.cons, constraint{op: op, v: v})
	}
	set.ok = len(set.cons) > 0
	return set
}

// contains reports whether v satisfies every constraint.
func (s versionSet) contains(v version) bool {
	if s.all {
		return true
	}
	for _, c := range s.cons {
		cmp := v.compare(c.v)
		var hold bool
		switch c.op {
		case "<":
			hold = cmp < 0
		case "<=":
			hold = cmp <= 0
		case ">":
			hold = cmp > 0
		case ">=":
			hold = cmp >= 0
		case "!=":
			hold = cmp != 0
		default:
			hold = cmp == 0
		}
		if !hold {
			return false
		}
	}
	return true
}

// String renders a version for tests and messages.
func (a version) String() string {
	parts := make([]string, len(a))
	for i, n := range a {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}
