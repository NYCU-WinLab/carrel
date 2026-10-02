package carrel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const Version = "0.7.0"

type D = map[string]any

func obj(v any) D {
	if d, ok := v.(map[string]any); ok && d != nil {
		return d
	}
	return D{}
}
func arr(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []D:
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return a
	case []string:
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return a
	}
	return []any{}
}
func dicts(v any) []D {
	r := []D{}
	for _, x := range arr(v) {
		r = append(r, obj(x))
	}
	return r
}
func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		n, _ := x.Float64()
		return n
	}
	n, _ := strconv.ParseFloat(str(v), 64)
	return n
}
func integer(v any) int  { return int(num(v)) }
func boolean(v any) bool { b, _ := v.(bool); return b }
func fallback(d D, k string, v any) any {
	if x, ok := d[k]; ok {
		return x
	}
	return v
}
func textAt(d D, k, def string) string { return str(fallback(d, k, def)) }
func intAt(d D, k string, def int) int { return integer(fallback(d, k, def)) }
func merge(ds ...D) D {
	d := D{}
	for _, x := range ds {
		for k, v := range x {
			d[k] = v
		}
	}
	return d
}
func pick(d D, keys ...string) D {
	r := D{}
	for _, k := range keys {
		if v, ok := d[k]; ok {
			r[k] = v
		}
	}
	return r
}
func without(d D, keys ...string) D {
	r := merge(d)
	for _, k := range keys {
		delete(r, k)
	}
	return r
}
func clone(d D) D          { var out D; must(json.Unmarshal(encoded(d), &out)); return out }
func encoded(v any) []byte { b, e := json.Marshal(v); must(e); return b }
func equal(a, b any) bool  { return string(encoded(a)) == string(encoded(b)) }
func contains(xs any, v any) bool {
	for _, x := range arr(xs) {
		if equal(x, v) {
			return true
		}
	}
	return false
}
func find(xs []D, f func(D) bool) D {
	for _, x := range xs {
		if f(x) {
			return x
		}
	}
	return nil
}
func filter(xs []D, f func(D) bool) []D {
	r := []D{}
	for _, x := range xs {
		if f(x) {
			r = append(r, x)
		}
	}
	return r
}
func now() float64  { return float64(time.Now().UnixNano()) / 1e9 }
func stamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func random(n int) string {
	b := make([]byte, n)
	_, e := rand.Read(b)
	must(e)
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomID() string {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	must(e)
	return hex.EncodeToString(b)
}
func digest(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func challenge(s string) string {
	v := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(v[:])
}
func matches(pattern, value string) bool { return regexp.MustCompile(pattern).MatchString(value) }
func must(err error) {
	if err != nil {
		panic(err)
	}
}

type Failure struct{ Result D }

func (f Failure) Error() string { return str(obj(f.Result["error"])["message"]) }
func fail(code, message string, details ...D) {
	panic(Failure{merge(D{"ok": false}, D{"error": merge(append([]D{{"code": code, "message": message}}, details...)...)})})
}
func failureResult(v any) D {
	if f, ok := v.(Failure); ok {
		return f.Result
	}
	return D{"ok": false, "error": D{"code": "conflict", "message": "Operation failed; allocation retained for repair"}}
}
func attempt(f func()) (err any) { defer func() { err = recover() }(); f(); return nil }
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Match existing Python receipt hashes so an interrupted migration does not replay an action.
func pythonJSON(v any) string {
	switch x := v.(type) {
	case map[string]any:
		ks := []string{}
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		s := []string{}
		for _, k := range ks {
			s = append(s, pythonJSON(k)+": "+pythonJSON(x[k]))
		}
		return "{" + strings.Join(s, ", ") + "}"
	case []any:
		s := []string{}
		for _, a := range x {
			s = append(s, pythonJSON(a))
		}
		return "[" + strings.Join(s, ", ") + "]"
	case []D:
		return pythonJSON(arr(x))
	case []string:
		return pythonJSON(arr(x))
	case string:
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range x {
			switch r {
			case '"', '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if r < 32 || r > 126 {
					for _, u := range utf16.Encode([]rune{r}) {
						fmt.Fprintf(&b, `\u%04x`, u)
					}
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
		return b.String()
	default:
		return string(encoded(v))
	}
}
