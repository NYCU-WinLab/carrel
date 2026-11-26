// Package snapshot is the plugin of the spike: one long operation, a
// snapshot, run as a task. It keeps one record per idempotency key on disk,
// so any process of the plugin, started at any time, answers for every
// operation: nothing lives only in memory.
package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/task"
)

const (
	Name    = "snapshot"
	Version = "0.1.0"
	Schema  = `{"type":"object","properties":{"seconds":{"type":"integer","minimum":1,"maximum":600}},"required":["seconds"]}`
)

// Op is an operation in the contract's terms, free of any generated type.
type Op struct {
	Key, State, Result, Error, Task, Message string
	Done                                     bool
	Progress                                 uint32
}

type record struct {
	Key       string `json:"key"`
	Operation string `json:"operation"`
	Task      string `json:"task"`
}

type Plugin struct {
	Dir string
	mu  sync.Mutex
}

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (p *Plugin) path(key string) string { return filepath.Join(p.Dir, "ops", key+".json") }

func (p *Plugin) Probe() (bool, string) {
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// Start starts the operation once per key; the same key again returns it.
func (p *Plugin) Start(key, operation, params string) (Op, error) {
	if !keyPattern.MatchString(key) {
		return Op{}, errors.New("idempotency_key must be 1 to 128 of A-Z a-z 0-9 . _ -")
	}
	if operation != Name {
		return Op{}, fmt.Errorf("unknown operation %q", operation)
	}
	var in struct {
		Seconds int `json:"seconds"`
	}
	if err := json.Unmarshal([]byte(params), &in); err != nil || in.Seconds < 1 || in.Seconds > 600 {
		return Op{}, errors.New("params must be {\"seconds\": 1 to 600}")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := os.Stat(p.path(key)); err == nil {
		return p.get(key)
	}
	id, err := task.Start(filepath.Join(p.Dir, "tasks"), in.Seconds*5, 200*time.Millisecond)
	if err != nil {
		return Op{}, err
	}
	b, _ := json.Marshal(record{Key: key, Operation: operation, Task: id})
	if err := os.MkdirAll(filepath.Dir(p.path(key)), 0o755); err != nil {
		return Op{}, err
	}
	if err := os.WriteFile(p.path(key)+".next", b, 0o644); err != nil {
		return Op{}, err
	}
	if err := os.Rename(p.path(key)+".next", p.path(key)); err != nil {
		return Op{}, err
	}
	return p.get(key)
}

func (p *Plugin) Get(key string) (Op, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.get(key)
}

func (p *Plugin) get(key string) (Op, error) {
	b, err := os.ReadFile(p.path(key))
	if err != nil {
		return Op{}, fmt.Errorf("no operation %q", key)
	}
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return Op{}, err
	}
	s, err := task.Get(filepath.Join(p.Dir, "tasks"), r.Task)
	if err != nil {
		return Op{}, err
	}
	op := Op{Key: key, Task: r.Task, Progress: uint32(s.Progress)}
	switch {
	case s.Running:
		op.State, op.Message = "running", fmt.Sprintf("snapshot %d%%", s.Progress)
	case s.Exit == "OK":
		op.State, op.Done, op.Progress, op.Result = "succeeded", true, 100, fmt.Sprintf(`{"snapshot":%q}`, "snap-"+key)
	case s.Exit == "cancelled":
		op.State, op.Done = "cancelled", true
	default:
		op.State, op.Done, op.Error = "failed", true, s.Exit
	}
	return op, nil
}

func (p *Plugin) Cancel(key string) (Op, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	op, err := p.get(key)
	if err != nil || op.Done {
		return op, err
	}
	if err := task.Stop(filepath.Join(p.Dir, "tasks"), op.Task); err != nil {
		return Op{}, err
	}
	return p.get(key)
}
