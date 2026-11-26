// Package scenarios runs the #563 spike scenarios against real processes:
// the host and the plugin are killed with SIGKILL, as a crash or an OOM
// kill would. Build the binaries into ../bin and the Python venv first (see
// ../README.md). RESULTS=path writes every run as JSON.
package scenarios

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const runs = 3

var root, _ = filepath.Abs("..")

type line map[string]any

// proc is a host or plugin process whose stdout lines arrive on a channel.
type proc struct {
	cmd   *exec.Cmd
	lines chan line
	done  chan struct{}
}

func start(t *testing.T, name string, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: cmd, lines: make(chan line, 1000), done: make(chan struct{})}
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			var l line
			if json.Unmarshal(s.Bytes(), &l) == nil {
				p.lines <- l
			}
		}
		_ = cmd.Wait()
		close(p.done)
	}()
	return p
}

// next waits for a line with this event, or for the process to end.
func (p *proc) next(t *testing.T, event string, within time.Duration) line {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			if l["event"] == event {
				return l
			}
			if l["event"] == "error" {
				return l
			}
		case <-p.done:
			select {
			case l := <-p.lines:
				if l["event"] == event || l["event"] == "error" {
					return l
				}
				continue
			default:
			}
			return nil
		case <-deadline:
			return nil
		}
	}
}

// until reads op lines until one is done, counting failed reads.
func (p *proc) until(within time.Duration) (last line, failed int) {
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			switch l["event"] {
			case "get_failed":
				failed++
			case "op":
				last = l
				if l["done"] == true {
					return last, failed
				}
			case "error":
				return l, failed
			}
		case <-p.done:
			return last, failed
		case <-deadline:
			return last, failed
		}
	}
}

func alive(pid int) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	// A zombie is not alive.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	return err == nil && !strings.Contains(string(b), ") Z ")
}

func pidOf(l line) int {
	if l == nil {
		return 0
	}
	f, _ := l["pid"].(float64)
	return int(f)
}

func kill(pid int) {
	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// pluginCmd is the plugin command line for an implementation.
func pluginCmd(impl, state string, goPlugin bool) []string {
	switch impl {
	case "go":
		if goPlugin {
			return []string{"bin/gp-plugin", "-state", state}
		}
		return []string{"bin/svc-plugin", "-state", state}
	case "go-contract1":
		if goPlugin {
			return []string{"bin/gp-plugin-v1", "-state", state}
		}
		return []string{"bin/svc-plugin-v1", "-state", state}
	case "python":
		if goPlugin {
			return []string{"python/run.sh", "--go-plugin", "--state", state}
		}
		return []string{"python/run.sh", "--state", state}
	}
	panic(impl)
}

type result map[string]any

var all []result

func record(t *testing.T, r result) {
	t.Helper()
	t.Logf("%v", r)
	all = append(all, r)
}

func TestMain(m *testing.M) {
	code := m.Run()
	if path := os.Getenv("RESULTS"); path != "" {
		b, _ := json.MarshalIndent(all, "", "  ")
		_ = os.WriteFile(path, append(b, '\n'), 0o644)
	}
	os.Exit(code)
}

// service starts a plugin service on a socket and waits until it listens.
func service(t *testing.T, impl, state, socket string) (*proc, int) {
	t.Helper()
	argv := append(pluginCmd(impl, state, false), "-socket", socket)
	if impl == "python" {
		argv[len(argv)-2] = "--socket"
	}
	p := start(t, argv[0], argv[1:]...)
	l := p.next(t, "listening", 15*time.Second)
	if l == nil {
		t.Fatalf("%s did not listen", impl)
	}
	return p, pidOf(l)
}

func gpHost(reattach string, impl, state string, args ...string) []string {
	a := []string{"-plugin", strings.Join(pluginCmd(impl, state, true), " ")}
	if reattach != "" {
		a = append(a, "-reattach", reattach)
	}
	return append(a, args...)
}

// The host (the agent) dies 1 s into a 4 s snapshot; a new host asks for
// the operation by its key.
func TestHostKilledMidOperation(t *testing.T) {
	for _, mech := range []string{"go-plugin", "go-plugin-reattach", "service"} {
		for _, impl := range []string{"go", "python"} {
			for run := 1; run <= runs; run++ {
				dir := t.TempDir()
				state, key := filepath.Join(dir, "state"), fmt.Sprintf("k%d", run)
				r := result{"scenario": "host_killed", "mechanism": mech, "plugin": impl, "run": run}
				var svcPid int
				var svc *proc
				socket := filepath.Join(dir, "p.sock")
				reattach := ""
				if mech == "go-plugin-reattach" {
					reattach = filepath.Join(dir, "reattach.json")
				}
				var host *proc
				if mech == "service" {
					svc, svcPid = service(t, impl, state, socket)
					host = start(t, root+"/bin/svc-host", "-socket", socket, "start", key, "4")
				} else {
					host = start(t, root+"/bin/gp-host", gpHost(reattach, impl, state, "start", key, "4")...)
				}
				pl := host.next(t, "plugin", 15*time.Second)
				pluginPid := pidOf(pl)
				if mech == "service" {
					pluginPid = svcPid
				}
				first := host.next(t, "op", 5*time.Second)
				time.Sleep(time.Second)
				kill(host.cmd.Process.Pid)
				<-host.done
				time.Sleep(500 * time.Millisecond)
				r["plugin_alive_after_host_kill"] = alive(pluginPid)
				began := time.Now()
				var again *proc
				if mech == "service" {
					again = start(t, root+"/bin/svc-host", "-socket", socket, "watch", key)
				} else {
					again = start(t, root+"/bin/gp-host", gpHost(reattach, impl, state, "watch", key)...)
				}
				pl2 := again.next(t, "plugin", 15*time.Second)
				r["reattached"] = pl2 != nil && pl2["reattached"] == true
				r["same_plugin_process"] = pidOf(pl2) == pluginPid || mech == "service"
				last, failed := again.until(20 * time.Second)
				r["recovered_ms"] = time.Since(began).Milliseconds()
				r["final_state"] = last["state"]
				r["same_task"] = first != nil && last != nil && first["task"] == last["task"]
				r["failed_reads"] = failed
				<-again.done
				time.Sleep(300 * time.Millisecond)
				// Left behind: the first plugin process when nothing reaps or reuses it.
				r["orphan_plugin_left"] = mech != "service" && pidOf(pl2) != pluginPid && alive(pluginPid)
				if reattach != "" {
					// The reattaching host leaves the plugin running by design.
					kill(pidOf(pl2))
				}
				kill(pluginPid)
				if svc != nil {
					kill(svcPid)
					<-svc.done
				}
				record(t, r)
				if r["final_state"] != "succeeded" {
					t.Errorf("%v", r)
				}
			}
		}
	}
}

// The plugin dies 1 s into a 4 s snapshot. go-plugin does not restart it:
// the host's reads fail until a new host launches a new plugin. A service
// is restarted by its supervisor (here, the test) and the same host goes on.
func TestPluginKilledMidOperation(t *testing.T) {
	for _, mech := range []string{"go-plugin", "service"} {
		for _, impl := range []string{"go", "python"} {
			for run := 1; run <= runs; run++ {
				dir := t.TempDir()
				state, key := filepath.Join(dir, "state"), fmt.Sprintf("k%d", run)
				socket := filepath.Join(dir, "p.sock")
				r := result{"scenario": "plugin_killed", "mechanism": mech, "plugin": impl, "run": run}
				var host, svc *proc
				var pluginPid int
				if mech == "service" {
					svc, pluginPid = service(t, impl, state, socket)
					host = start(t, root+"/bin/svc-host", "-socket", socket, "start", key, "4")
					host.next(t, "plugin", 15*time.Second)
				} else {
					host = start(t, root+"/bin/gp-host", gpHost("", impl, state, "start", key, "4")...)
					pluginPid = pidOf(host.next(t, "plugin", 15*time.Second))
				}
				first := host.next(t, "op", 5*time.Second)
				time.Sleep(time.Second)
				kill(pluginPid)
				began := time.Now()
				if mech == "service" {
					<-svc.done
					time.Sleep(500 * time.Millisecond)
					svc, pluginPid = service(t, impl, state, socket)
					last, failed := host.until(20 * time.Second)
					r["same_host_recovered"] = last != nil && last["state"] == "succeeded"
					r["final_state"], r["failed_reads"] = last["state"], failed
					r["same_task"] = first != nil && last != nil && first["task"] == last["task"]
					r["recovered_ms"] = time.Since(began).Milliseconds()
					kill(pluginPid)
					<-svc.done
				} else {
					// Give the host 3 s with a dead plugin.
					last, failed := host.until(3 * time.Second)
					r["same_host_recovered"] = last != nil && last["state"] == "succeeded"
					r["failed_reads"] = failed
					select {
					case <-host.done:
						r["host_exited"] = true
					default:
						r["host_exited"] = false
						kill(host.cmd.Process.Pid)
						<-host.done
					}
					again := start(t, root+"/bin/gp-host", gpHost("", impl, state, "watch", key)...)
					again.next(t, "plugin", 15*time.Second)
					last, _ = again.until(20 * time.Second)
					r["final_state"] = last["state"]
					r["same_task"] = first != nil && last != nil && first["task"] == last["task"]
					r["recovered_ms"] = time.Since(began).Milliseconds()
					<-again.done
				}
				record(t, r)
				if r["final_state"] != "succeeded" {
					t.Errorf("%v", r)
				}
			}
		}
	}
}

// A contract 1 plugin (built before Operation.message) with a host that
// serves contracts 1 and 2, and with one that serves only 2.
func TestOlderContract(t *testing.T) {
	for _, mech := range []string{"go-plugin", "service"} {
		for run := 1; run <= runs; run++ {
			dir := t.TempDir()
			state, socket := filepath.Join(dir, "state"), filepath.Join(dir, "p.sock")
			r := result{"scenario": "older_contract", "mechanism": mech, "plugin": "go-contract1", "run": run}
			var host, refused, svc *proc
			var svcPid int
			if mech == "service" {
				svc, svcPid = service(t, "go-contract1", state, socket)
				host = start(t, root+"/bin/svc-host", "-socket", socket, "start", "k", "1")
				refused = start(t, root+"/bin/svc-host", "-socket", socket, "-min-contract", "2", "describe")
			} else {
				host = start(t, root+"/bin/gp-host", gpHost("", "go-contract1", state, "start", "k", "1")...)
				refused = start(t, root+"/bin/gp-host", append([]string{"-versions", "2"}, gpHost("", "go-contract1", state, "describe")...)...)
			}
			pl := host.next(t, "plugin", 15*time.Second)
			r["negotiated"] = pl["version"]
			if pl["contract"] != nil {
				r["negotiated"] = pl["contract"]
			}
			last, _ := host.until(15 * time.Second)
			r["final_state"] = last["state"]
			r["message_empty"] = last["message"] == ""
			e := refused.next(t, "error", 15*time.Second)
			r["refusal"] = e["error"]
			<-host.done
			<-refused.done
			if svc != nil {
				kill(svcPid)
				<-svc.done
			}
			record(t, r)
			if r["final_state"] != "succeeded" || r["refusal"] == nil {
				t.Errorf("%v", r)
			}
		}
	}
}

// The same key twice starts one task.
func TestSameKeyStartsOnce(t *testing.T) {
	for _, mech := range []string{"go-plugin", "service"} {
		for _, impl := range []string{"go", "python"} {
			dir := t.TempDir()
			state, socket := filepath.Join(dir, "state"), filepath.Join(dir, "p.sock")
			var a, b, svc *proc
			var svcPid int
			if mech == "service" {
				svc, svcPid = service(t, impl, state, socket)
				a = start(t, root+"/bin/svc-host", "-socket", socket, "start", "k", "1")
				b = start(t, root+"/bin/svc-host", "-socket", socket, "start", "k", "1")
			} else {
				// 2 hosts, each with its own plugin process on the same state.
				a = start(t, root+"/bin/gp-host", gpHost("", impl, state, "start", "k", "1")...)
				b = start(t, root+"/bin/gp-host", gpHost("", impl, state, "start", "k", "1")...)
			}
			la, _ := a.until(15 * time.Second)
			lb, _ := b.until(15 * time.Second)
			tasks, _ := filepath.Glob(filepath.Join(state, "tasks", "*.pid"))
			r := result{"scenario": "same_key", "mechanism": mech, "plugin": impl, "run": 1,
				"tasks_started": len(tasks), "same_task": la != nil && lb != nil && la["task"] == lb["task"]}
			<-a.done
			<-b.done
			if svc != nil {
				kill(svcPid)
				<-svc.done
			}
			record(t, r)
		}
	}
}
