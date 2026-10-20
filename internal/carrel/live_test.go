package carrel

// TestLiveRows reads a copy of a production database. Every stored row must
// come out of a typed decode and encode with the same bytes as the D path
// gives today. It prints only kinds, keys, JSON types and counts, never
// values, so it can run where the database lives:
//
//	go test -c -o carrel.test ./internal/carrel   (on the build host)
//	CARREL_LIVE_DB=/tmp/carrel-copy.db ./carrel.test -test.run TestLiveRows -test.v

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// liveTyped holds the typed round trip of each kind that has one. A kind
// without an entry uses the D path, which is the reference.
var liveTyped = map[string]func(data string) string{
	"keys":          roundTrip[sshKey],
	"certificates":  roundTrip[certificateRecord],
	"storage_usage": roundTrip[storageUsage],
	"guest_reports": roundTrip[guestReport],
	"ports":         roundTrip[portGrant],
	"peers":         roundTrip[peerGrant],
	"domains":       roundTrip[domainRecord],
}

func roundTrip[T any](data string) string {
	var v T
	must(json.Unmarshal([]byte(data), &v))
	return string(encoded(v))
}

// label hides keys that are data rather than field names: IDs, VMIDs.
// Field names are lower case words joined by underscores.
func label(k string) string {
	if !matches(`^[a-z]+(_[a-z]+)*$`, k) {
		return "<key>"
	}
	return k
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	}
	return "object"
}

func TestLiveRows(t *testing.T) {
	path := os.Getenv("CARREL_LIVE_DB")
	if path == "" {
		t.Skip("CARREL_LIVE_DB not set")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	must(err)
	defer db.Close()
	rows, err := db.Query(`SELECT kind, data FROM objects
		UNION ALL SELECT 'oauth/' || kind, data FROM oauth
		UNION ALL SELECT 'tenant_quota', quota FROM tenants`)
	must(err)
	defer rows.Close()
	type stat struct{ rows, rewritten, typed, mismatched int }
	stats := map[string]*stat{}
	census := map[string]int{}
	for rows.Next() {
		var kind, data string
		must(rows.Scan(&kind, &data))
		s := stats[kind]
		if s == nil {
			s = &stat{}
			stats[kind] = s
		}
		s.rows++
		d := decode(data)
		reference := string(encoded(d))
		if reference != data {
			// Written in another format (older code); the next save rewrites it.
			s.rewritten++
		}
		if typed := liveTyped[kind]; typed != nil {
			s.typed++
			if typed(data) != reference {
				s.mismatched++
			}
		}
		for k, v := range d {
			census[kind+" "+label(k)+" "+jsonType(v)]++
			if inner, ok := v.(map[string]any); ok {
				for k2, v2 := range inner {
					census[kind+" "+label(k)+"."+label(k2)+" "+jsonType(v2)]++
				}
			}
		}
	}
	must(rows.Err())
	kinds := make([]string, 0, len(stats))
	for k := range stats {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := stats[k]
		t.Logf("kind %s rows=%d rewritten=%d typed=%d mismatched=%d", k, s.rows, s.rewritten, s.typed, s.mismatched)
		if s.mismatched > 0 {
			t.Errorf("%s: %d rows change bytes through the typed path", k, s.mismatched)
		}
	}
	lines := make([]string, 0, len(census))
	for k, n := range census {
		lines = append(lines, fmt.Sprintf("field %s %d", k, n))
	}
	sort.Strings(lines)
	t.Log("\n" + strings.Join(lines, "\n"))
}
