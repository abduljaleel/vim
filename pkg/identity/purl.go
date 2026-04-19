package identity

import (
	"fmt"
	"net/url"
	"strings"
)

// PURL models a Package URL per the pURL specification (ECMA-427).
// Canonical form: scheme:type/namespace/name@version?qualifiers#subpath
// where scheme is always "pkg".
//
// See https://github.com/package-url/purl-spec for the full specification.
//
// The prototype implements parsing and string rendering. Full normalization
// rules (e.g., type-specific case folding for namespaces) are deferred
// until ingestion layers require them.
type PURL struct {
	Type       string            // e.g. "npm", "pypi", "golang", "github"
	Namespace  string            // optional; may contain slashes
	Name       string            // required
	Version    string            // optional
	Qualifiers map[string]string // optional key-value pairs
	Subpath    string            // optional
}

// ParsePURL parses a canonical pURL string.
//
// Examples accepted by the prototype:
//   pkg:npm/lodash@4.17.21
//   pkg:golang/github.com/abduljaleel/vim@v0.1.0
//   pkg:pypi/requests@2.31.0
//   pkg:github/openssf/scorecard@v4
func ParsePURL(raw string) (PURL, error) {
	if !strings.HasPrefix(raw, "pkg:") {
		return PURL{}, fmt.Errorf("invalid pURL %q: must begin with 'pkg:'", raw)
	}
	body := raw[len("pkg:"):]

	// Subpath split.
	var subpath string
	if i := strings.Index(body, "#"); i >= 0 {
		subpath = body[i+1:]
		body = body[:i]
	}

	// Qualifier split.
	var qualRaw string
	if i := strings.Index(body, "?"); i >= 0 {
		qualRaw = body[i+1:]
		body = body[:i]
	}

	// Type split — first slash.
	slash := strings.IndexByte(body, '/')
	if slash < 0 {
		return PURL{}, fmt.Errorf("invalid pURL %q: missing type separator", raw)
	}
	pType := body[:slash]
	rest := body[slash+1:]
	if pType == "" {
		return PURL{}, fmt.Errorf("invalid pURL %q: empty type", raw)
	}

	// Version split.
	var version string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		version = rest[i+1:]
		rest = rest[:i]
	}

	// Namespace / name.
	var namespace, name string
	if last := strings.LastIndexByte(rest, '/'); last >= 0 {
		namespace = rest[:last]
		name = rest[last+1:]
	} else {
		name = rest
	}
	if name == "" {
		return PURL{}, fmt.Errorf("invalid pURL %q: empty name", raw)
	}

	quals, err := parseQualifiers(qualRaw)
	if err != nil {
		return PURL{}, fmt.Errorf("invalid pURL %q: %w", raw, err)
	}

	return PURL{
		Type:       strings.ToLower(pType),
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: quals,
		Subpath:    subpath,
	}, nil
}

func parseQualifiers(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("malformed qualifier %q", pair)
		}
		k := strings.ToLower(pair[:eq])
		v, err := url.QueryUnescape(pair[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("malformed qualifier value %q: %w", pair, err)
		}
		out[k] = v
	}
	return out, nil
}

// String renders the pURL in canonical form.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(p.Namespace)
		b.WriteByte('/')
	}
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}
	if len(p.Qualifiers) > 0 {
		b.WriteByte('?')
		first := true
		for k, v := range p.Qualifiers {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	if p.Subpath != "" {
		b.WriteByte('#')
		b.WriteString(p.Subpath)
	}
	return b.String()
}
