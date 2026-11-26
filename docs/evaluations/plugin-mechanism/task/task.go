// Package task stands in for a Proxmox task: a worker in its own session
// that outlives whoever started it, known by an id, with progress and an
// exit status in files, as pvedaemon keeps them under /var/log/pve/tasks.
package task

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Status struct {
	Running  bool
	Progress int
	// Exit is "OK", "cancelled", or a failure; empty while running.
	Exit string
}

// Start runs a task of steps steps, step long each, under dir.
func Start(dir string, steps int, step time.Duration) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	id := fmt.Sprintf("UPID:fake:%d", time.Now().UnixNano())
	base := filepath.Join(dir, strings.ReplaceAll(id, ":", "_"))
	script := fmt.Sprintf(`i=0; while [ $i -lt %d ]; do i=$((i+1)); echo $((i*100/%d)) > %q.progress; sleep %s; done; echo OK > %q.exit`,
		steps, steps, base, strconv.FormatFloat(step.Seconds(), 'f', 3, 64), base)
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	if err := os.WriteFile(base+".pid", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		return "", err
	}
	// Reap it here while this process lives; after that, init does.
	go func() { _ = cmd.Wait() }()
	return id, nil
}

func paths(dir, id string) string { return filepath.Join(dir, strings.ReplaceAll(id, ":", "_")) }

func pid(base string) int {
	b, _ := os.ReadFile(base + ".pid")
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// Get reads a task's status. A worker gone with no exit status failed.
func Get(dir, id string) (Status, error) {
	base := paths(dir, id)
	if _, err := os.Stat(base + ".pid"); err != nil {
		return Status{}, fmt.Errorf("no task %s", id)
	}
	b, _ := os.ReadFile(base + ".progress")
	progress, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if e, err := os.ReadFile(base + ".exit"); err == nil {
		return Status{Progress: progress, Exit: strings.TrimSpace(string(e))}, nil
	}
	if p := pid(base); p > 0 && syscall.Kill(p, 0) == nil {
		return Status{Running: true, Progress: progress}, nil
	}
	return Status{Progress: progress, Exit: "task worker is gone"}, nil
}

// Stop ends a running task as cancelled.
func Stop(dir, id string) error {
	base := paths(dir, id)
	if p := pid(base); p > 0 {
		_ = syscall.Kill(-p, syscall.SIGTERM)
	}
	if _, err := os.Stat(base + ".exit"); err == nil {
		return nil
	}
	return os.WriteFile(base+".exit", []byte("cancelled\n"), 0o644)
}
