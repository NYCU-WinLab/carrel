package carrel

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The guests call 10.200.0.3:8080 directly, so the gateway does not route
// /internal/*, and a request from the gateway's own address (which carries
// internet clients) is refused there before any handler runs (#262).
func TestInternalPathsAreNotReachableThroughTheGateway(t *testing.T) {
	for _, c := range controlPaths {
		if strings.HasPrefix("/internal/guest-keys", strings.TrimSuffix(c, "*")) && strings.HasSuffix(c, "/*") {
			t.Errorf("the gateway routes %s to carrel", c)
		}
	}
	p, _ := fixture(t)
	a := NewApp(p, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/internal/guest-status"},
		{"POST", "/internal/guest-status"},
		{"POST", "/internal/guest-keys"},
	} {
		req := httptest.NewRequest(c.method, "http://carrel.test"+c.path, strings.NewReader(`{}`))
		req.RemoteAddr = "10.200.0.2:40000"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != 403 || !strings.Contains(w.Body.String(), `"forbidden"`) {
			t.Errorf("%s %s from the gateway: %d %s, want the source check's 403", c.method, c.path, w.Code, w.Body.String())
		}
	}
}
