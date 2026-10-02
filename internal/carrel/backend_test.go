package carrel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdapterFailureIsBoundedAndCorrelated(t *testing.T) {
	dir := t.TempDir()
	must(os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nprintf '%s' '{\"ok\":false,\"error_code\":\"command_failed\",\"error\":\"secret-node-output\"}'\nexit 1\n"), 0700))
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	b := &SSHBackend{Config: "unused"}
	ctx := context.WithValue(context.Background(), operationLogKey{}, "op-test")
	_, err := b.Call(ctx, D{"op": "action", "action": "resize", "request_id": "receipt-test"}, "carrel-node")
	if err == nil {
		t.Fatal("failed backend accepted")
	}
	result := failureResult(err)
	detail := obj(result["error"])
	if detail["code"] != "backend_unavailable" || detail["backend_code"] != "command_failed" || detail["operation"] != "op-test" || detail["request_id"] != "receipt-test" || strings.Contains(string(encoded(result)), "secret-node-output") {
		t.Fatalf("unsafe or unhelpful adapter failure: %s", encoded(result))
	}
}
