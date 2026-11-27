package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// run is one operation under its idempotency key, as the state directory
// keeps it. It is written before the request that starts the PVE task, and
// again with the task's UPID, so a plugin that restarts finds the task
// again, or learns that it never started.
type run struct {
	Key       string `json:"key"`
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	VMID      int    `json:"vmid"`
	Name      string `json:"name"`
	// SentAt is when the start request was about to go, in Unix seconds.
	SentAt int64  `json:"sent_at"`
	UPID   string `json:"upid,omitempty"`
	// Done runs keep their outcome: a later call answers the same.
	Done      bool   `json:"done,omitempty"`
	State     string `json:"state,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type store struct{ dir string }

func (s store) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

// load is the run of key, or nil when there is none.
func (s store) load(key string) (*run, error) {
	raw, err := os.ReadFile(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r run
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// save writes the run so that it survives a crash: a temporary file,
// synced, renamed over the old one, and the directory synced.
func (s store) save(r *run) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	path := s.path(r.Key)
	f, err := os.CreateTemp(s.dir, ".run-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
