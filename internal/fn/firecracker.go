//go:build linux

package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	guestAddr = "172.16.0.2"
	hostCIDR  = "172.16.0.1/30"
	// Every snapshot expects these two addresses: a restored guest keeps the
	// ARP entry of the tap it had when the snapshot was taken.
	hostMAC     = "06:00:ac:10:00:01"
	guestMAC    = "06:00:ac:10:00:02"
	controlPort = 1
	bootArgs    = "console=ttyS0 quiet loglevel=0 reboot=k panic=1 pci=off ro init=/.fn/init " +
		"i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on"
)

// Firecracker wakes functions by restoring Firecracker snapshots. Each
// instance runs in its own network namespace, so every guest can use the
// same address.
type Firecracker struct {
	Binary string // firecracker executable
	Kernel string // guest kernel, used when a snapshot is built
	RunDir string // API sockets
	slots  chan *slot
}

type slot struct {
	name string
	ns   *os.File
}

// NewFirecracker prepares `slots` network namespaces named <prefix>0, <prefix>1, ...
func NewFirecracker(binary, kernel, runDir, prefix string, slots int) (*Firecracker, error) {
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, err
	}
	fc := &Firecracker{Binary: binary, Kernel: kernel, RunDir: runDir, slots: make(chan *slot, slots)}
	for i := range slots {
		s, err := newSlot(prefix + strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		fc.slots <- s
	}
	return fc, nil
}

func newSlot(name string) (*slot, error) {
	_ = exec.Command("ip", "netns", "del", name).Run() // left over from an earlier run
	steps := [][]string{
		{"netns", "add", name},
		{"-n", name, "link", "set", "lo", "up"},
		{"-n", name, "tuntap", "add", "dev", "tap0", "mode", "tap"},
		{"-n", name, "link", "set", "tap0", "address", hostMAC},
		{"-n", name, "addr", "add", hostCIDR, "dev", "tap0"},
		{"-n", name, "link", "set", "tap0", "up"},
		{"-n", name, "neigh", "replace", guestAddr, "lladdr", guestMAC, "dev", "tap0", "nud", "permanent"},
	}
	for _, args := range steps {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ip %v: %w: %s", args, err, bytes.TrimSpace(out))
		}
	}
	ns, err := os.Open("/run/netns/" + name)
	if err != nil {
		return nil, err
	}
	return &slot{name: name, ns: ns}, nil
}

// Close removes the namespaces. Call it after every instance stopped.
func (fc *Firecracker) Close() {
	for {
		select {
		case s := <-fc.slots:
			s.ns.Close()
			_ = exec.Command("ip", "netns", "del", s.name).Run()
		default:
			return
		}
	}
}

// inNamespace runs do on a thread that is inside the slot's network
// namespace. Sockets and child processes created there stay in it.
func (s *slot) inNamespace(do func() error) error {
	runtime.LockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer original.Close()
	if err := unix.Setns(int(s.ns.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	result := do()
	if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
		// The thread stays locked, so Go discards it when this goroutine ends
		// and no other goroutine runs in the wrong namespace.
		return errors.Join(result, fmt.Errorf("leave namespace: %w", err))
	}
	runtime.UnlockOSThread()
	return result
}

func (s *slot) dial(ctx context.Context, port int) (net.Conn, error) {
	var conn net.Conn
	err := s.inNamespace(func() error {
		var dialErr error
		conn, dialErr = (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(guestAddr, strconv.Itoa(port)))
		return dialErr
	})
	if err != nil && conn != nil {
		conn.Close()
		conn = nil
	}
	return conn, err
}

type vm struct {
	fc   *Firecracker
	slot *slot
	port int
	cmd  *exec.Cmd
	sock string
	api  *http.Client
	done chan struct{}
	stop sync.Once
}

// start launches a Firecracker process in a free slot. The caller configures
// it through the API and must call Stop.
func (fc *Firecracker) start(ctx context.Context, logPath string, port int) (*vm, error) {
	var s *slot
	select {
	case s = <-fc.slots:
	default:
		return nil, ErrBusy
	}
	sock := filepath.Join(fc.RunDir, s.name+".sock")
	_ = os.Remove(sock)
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fc.slots <- s
		return nil, err
	}
	defer log.Close()
	cmd := exec.Command(fc.Binary, "--api-sock", sock)
	cmd.Stdout = log
	cmd.Stderr = log
	// No Pdeathsig: it follows the starting thread, not the process, and
	// Go may discard a thread that could not leave the namespace.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.inNamespace(cmd.Start); err != nil {
		fc.slots <- s
		return nil, err
	}
	v := &vm{fc: fc, slot: s, port: port, cmd: cmd, sock: sock, done: make(chan struct{})}
	v.api = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	go func() {
		_ = cmd.Wait()
		close(v.done)
	}()
	// The socket file appears before Firecracker listens on it.
	err = retry(ctx, v.done, time.Millisecond, func() error {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			conn.Close()
		}
		return err
	})
	if err != nil {
		v.Stop()
		return nil, fmt.Errorf("firecracker API: %w", err)
	}
	return v, nil
}

func (v *vm) Dial(ctx context.Context) (net.Conn, error) { return v.slot.dial(ctx, v.port) }
func (v *vm) Done() <-chan struct{}                      { return v.done }

func (v *vm) Stop() {
	v.stop.Do(func() {
		_ = v.cmd.Process.Kill()
		<-v.done
		v.api.CloseIdleConnections()
		_ = os.Remove(v.sock)
		v.fc.slots <- v.slot
	})
}

func (v *vm) call(ctx context.Context, method, path string, body any) error {
	content, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.api.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(message))
	}
	return nil
}

// guest sends one HTTP request to a port inside the instance.
func (v *vm) guest(ctx context.Context, method string, port int, path, body string) (int, error) {
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return v.slot.dial(ctx, port) },
	}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, "http://function"+path, bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// retry calls try until it succeeds, the context ends or the VM dies.
func retry(ctx context.Context, dead <-chan struct{}, pause time.Duration, try func() error) error {
	for {
		err := try()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-dead:
			return errors.Join(errors.New("the microVM stopped"), err)
		case <-time.After(pause):
		}
	}
}

// Wake restores the function's snapshot and brings the guest up to date.
func (fc *Firecracker) Wake(ctx context.Context, f Function) (Instance, error) {
	v, err := fc.start(ctx, filepath.Join(filepath.Dir(filepath.Dir(f.Dir)), "log"), f.Port)
	if err != nil {
		return nil, err
	}
	err = v.call(ctx, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": filepath.Join(f.Dir, "snap.state"),
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": filepath.Join(f.Dir, "snap.mem")},
		"resume_vm":     true,
	})
	if err == nil {
		err = v.setClock(ctx)
	}
	if err == nil && f.WakePath != "" {
		var status int
		status, err = v.guest(ctx, http.MethodPost, f.Port, f.WakePath, "")
		if err == nil && status >= 500 {
			err = fmt.Errorf("wake_path answered %d", status)
		}
	}
	if err != nil {
		v.Stop()
		return nil, err
	}
	return v, nil
}

// setClock gives the guest the current time: a restored guest reads the time
// of its snapshot.
func (v *vm) setClock(ctx context.Context) error {
	return retry(ctx, v.done, 2*time.Millisecond, func() error {
		status, err := v.guest(ctx, http.MethodPost, controlPort, "/clock", strconv.FormatInt(time.Now().UnixNano(), 10))
		if err == nil && status != http.StatusNoContent {
			err = fmt.Errorf("guest clock: %d", status)
		}
		return err
	})
}

// snapshot cold-boots a root file system, waits until the function answers
// and writes snap.state and snap.mem next to it.
func (fc *Firecracker) snapshot(ctx context.Context, f Function, logPath string) error {
	v, err := fc.start(ctx, logPath, f.Port)
	if err != nil {
		return err
	}
	defer v.Stop()
	steps := []struct {
		path string
		body any
	}{
		{"/boot-source", map[string]string{"kernel_image_path": fc.Kernel, "boot_args": bootArgs}},
		{"/drives/rootfs", map[string]any{
			"drive_id": "rootfs", "path_on_host": filepath.Join(f.Dir, "rootfs.ext4"),
			"is_root_device": true, "is_read_only": true,
		}},
		{"/network-interfaces/eth0", map[string]string{"iface_id": "eth0", "guest_mac": guestMAC, "host_dev_name": "tap0"}},
		{"/machine-config", map[string]int{"vcpu_count": 1, "mem_size_mib": f.MemoryMB}},
		{"/actions", map[string]string{"action_type": "InstanceStart"}},
	}
	for _, step := range steps {
		if err := v.call(ctx, http.MethodPut, step.path, step.body); err != nil {
			return err
		}
	}
	// Ready means any HTTP answer below 500 within 60 seconds, the rule apps use (PLAN 7.9).
	ready, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	err = retry(ready, v.done, 20*time.Millisecond, func() error {
		attempt, stop := context.WithTimeout(ready, 2*time.Second)
		defer stop()
		status, err := v.guest(attempt, http.MethodGet, f.Port, "/", "")
		if err == nil && status >= 500 {
			err = fmt.Errorf("function answered %d", status)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("function was not ready: %w", err)
	}
	time.Sleep(time.Second) // let the function settle before it is frozen
	if err := v.call(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"}); err != nil {
		return err
	}
	return v.call(ctx, http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_type": "Full",
		"snapshot_path": filepath.Join(f.Dir, "snap.state"),
		"mem_file_path": filepath.Join(f.Dir, "snap.mem"),
	})
}
