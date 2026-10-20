package carrel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

const Version = "0.10.0"

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
func clone(d D) D { var out D; must(json.Unmarshal(encoded(d), &out)); return out }

// encoded is the one JSON encoder for stored rows, adapter requests, hashes
// and responses. A struct encodes its fields in declaration order, so a value
// that holds one is re-encoded with object keys sorted and numbers as
// written: a struct gives the bytes its map form gives.
func encoded(v any) []byte {
	b, e := json.Marshal(v)
	must(e)
	if plain(v) {
		return b
	}
	var tree any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	must(d.Decode(&tree))
	b, e = json.Marshal(tree)
	must(e)
	return b
}

// plain reports whether v holds only maps, slices and scalars, whose
// encoding already sorts keys at every level.
func plain(v any) bool {
	switch x := v.(type) {
	case nil, bool, string, float64, int, int64, json.Number, []string, []int, map[string]string:
		return true
	case D:
		for _, y := range x {
			if !plain(y) {
				return false
			}
		}
		return true
	case []any:
		for _, y := range x {
			if !plain(y) {
				return false
			}
		}
		return true
	case []D:
		for _, y := range x {
			if !plain(y) {
				return false
			}
		}
		return true
	}
	return false
}
func equal(a, b any) bool { return string(encoded(a)) == string(encoded(b)) }
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

// randomSource is a variable so the golden tests can repeat IDs and tokens.
var randomSource io.Reader = rand.Reader

func random(n int) string {
	b := make([]byte, n)
	_, e := io.ReadFull(randomSource, b)
	must(e)
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomID() string {
	b := make([]byte, 16)
	_, e := io.ReadFull(randomSource, b)
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
