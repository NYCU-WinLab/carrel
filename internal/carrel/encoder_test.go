package carrel

import (
	"encoding/json"
	"testing"
)

func TestAStructEncodesLikeItsMap(t *testing.T) {
	type nic struct {
		Network string `json:"network"`
		Index   int    `json:"index"`
	}
	type machine struct {
		VMID   int            `json:"vmid"`
		Name   string         `json:"name"`
		CPU    float64        `json:"cpu"`
		Seen   json.Number    `json:"created_at"`
		NICs   []nic          `json:"nics"`
		Extra  map[string]any `json:"extra,omitempty"`
		Reason *string        `json:"reason"`
	}
	typed := machine{VMID: 10100, Name: "web <a&b>", CPU: 1.5, Seen: "1792499082.4361117", NICs: []nic{{"p00101", 1}}}
	plainForm := D{"vmid": 10100, "name": "web <a&b>", "cpu": 1.5, "created_at": 1792499082.4361117, "nics": []any{D{"network": "p00101", "index": 1}}, "reason": nil}
	if got, want := string(encoded(typed)), string(encoded(plainForm)); got != want {
		t.Fatalf("struct %s\nmap    %s", got, want)
	}
	// Inside a map, at any depth.
	if got, want := string(encoded(D{"op": "create", "machine": typed})), string(encoded(D{"op": "create", "machine": plainForm})); got != want {
		t.Fatalf("nested %s\nmap    %s", got, want)
	}
}

func TestPlainValuesKeepTheirOneEncoding(t *testing.T) {
	// Invalid UTF-8 encodes as � once; a second pass would write the raw
	// character instead, so plain values must not be re-encoded.
	v := D{"b": []any{1, "x\xff", D{"d": true}}, "a": []D{{"z": nil}}}
	direct, err := json.Marshal(v)
	must(err)
	if string(encoded(v)) != string(direct) || !plain(v) {
		t.Fatal(string(encoded(v)))
	}
}
