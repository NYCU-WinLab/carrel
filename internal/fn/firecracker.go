//go:build linux

package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

	// Paths inside a jail. A snapshot records the path of its root file
	// system, so the build and every wake use the same ones.
	jailDir      = "/fn"
	jailRootfs   = jailDir + "/rootfs.ext4"
	jailKernel   = jailDir + "/vmlinux"
	jailState    = jailDir + "/snap.state"
	jailMemory   = jailDir + "/snap.mem"
	jailSocket   = "/api.sock"
	cgroupParent = "carrel-fn"
	cgroupRoot   = "/sys/fs/cgroup"
	// Memory a Firecracker process may use beyond its guest's memory.
	overheadMB = 128
	maxPIDs    = 64
)

// Config locates what a function host needs to run microVMs.
type Config struct {
	Firecracker string // firecracker executable
	Jailer      string // jailer executable
	Kernel      string // guest kernel, used when a snapshot is built
	// JailBase holds one directory per running instance. It must be on the
	// file system of the functions, because a jail gets hard links to them.
	JailBase string
	// Prefix and First name the network namespaces: <prefix><first>, ...
	Prefix string
	First  int
	Slots  int
	// UIDBase + slot index is the user a slot's Firecracker runs as, so one
	// instance cannot signal or read another. GID is shared: it reads the
	// function files.
	UIDBase int
	GID     int
	// EgressFirst + slot index numbers the slot's link to the host, which
	// gives it a route to the internet (egress.go).
	EgressFirst int
	Egress      Egress
	// Router is true for the long-running router, which owns the host's
	// rule table, and false for a build.
	Router bool
}

// Firecracker wakes functions by restoring Firecracker snapshots. Each
// instance runs under the jailer (PLAN 7.11): its own root directory, user,
// cgroup, PID namespace and network namespace.
type Firecracker struct {
	cfg   Config
	slots chan *slot
	// recycling counts slots that are being cleaned in the background.
	// mu guards closed, so no slot starts recycling after Close began.
	recycling sync.WaitGroup
	mu        sync.Mutex
	closed    bool
	// netMu keeps Guard from checking a namespace that is being made again.
	netMu sync.Mutex
	// hostRules and slotRules are how nft lists the two tables when they
	// are as loaded (expectedListing). Guard compares against them.
	hostRules, slotRules string
}

type slot struct {
	name string
	uid  int
	link int
	// mu guards ns against a dial that arrives after the slot was recycled:
	// a closed descriptor's number can already name another namespace.
	mu     sync.RWMutex
	ns     *os.File
	closed bool
}

func (s *slot) close() {
	s.mu.Lock()
	s.closed = true
	s.ns.Close()
	s.mu.Unlock()
}

// NewFirecracker prepares the cgroup and one network namespace per slot.
func NewFirecracker(cfg Config) (*Firecracker, error) {
	if err := os.MkdirAll(cfg.JailBase, 0o711); err != nil {
		return nil, err
	}
	if err := prepareCgroup(); err != nil {
		return nil, err
	}
	egress, err := cfg.Egress.resolve()
	if err != nil {
		return nil, err
	}
	cfg.Egress = egress
	if err := prepareHost(cfg.Egress, cfg.Router); err != nil {
		return nil, err
	}
	fc := &Firecracker{cfg: cfg, slots: make(chan *slot, cfg.Slots)}
	if cfg.Router {
		if fc.hostRules, err = expectedListing(hostRules(cfg.Egress)); err != nil {
			return nil, err
		}
		if fc.slotRules, err = expectedListing(insideRules(cfg.Egress)); err != nil {
			return nil, err
		}
		// The router just loaded the host table. It must already match.
		if listing, err := listTable(""); err != nil || listing != fc.hostRules {
			return nil, fmt.Errorf("the host rule table is not as loaded: %v", err)
		}
	}
	for i := range cfg.Slots {
		name := cfg.Prefix + strconv.Itoa(cfg.First+i)
		// A daemon that crashed leaves its Firecracker processes running.
		if err := fc.cleanup(name); err != nil {
			fc.Close()
			return nil, err
		}
		s, err := newSlot(name, cfg.UIDBase+cfg.First+i, cfg.GID, cfg.EgressFirst+i, cfg.Egress)
		if err != nil {
			fc.Close()
			return nil, err
		}
		fc.slots <- s
	}
	return fc, nil
}

// Guard puts the rule tables back when something removed or changed them,
// such as `nft flush ruleset` or a firewall service that restarted. The
// slots' own tables keep private addresses blocked even then, but the host
// stops dropping what functions send to it, and egress stops. Only the
// router guards; call it every few seconds.
func (fc *Firecracker) Guard() {
	if !fc.cfg.Router {
		return
	}
	fc.netMu.Lock()
	defer fc.netMu.Unlock()
	fc.mu.Lock()
	closed := fc.closed
	fc.mu.Unlock()
	if closed {
		return
	}
	forward, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	// A table that cannot be listed counts as changed: it is loaded again.
	if listing, err := listTable(""); err != nil || listing != fc.hostRules || string(bytes.TrimSpace(forward)) != "1" {
		if err := prepareHost(fc.cfg.Egress, true); err != nil {
			slog.Error("rule table not restored", "table", "host", "error", err)
		} else {
			slog.Warn("rule table restored", "table", "host")
			fc.hostRules = relisted("", fc.hostRules, hostRules(fc.cfg.Egress))
		}
	}
	for i := range fc.cfg.Slots {
		name := fc.cfg.Prefix + strconv.Itoa(fc.cfg.First+i)
		if _, err := os.Stat("/run/netns/" + name); err != nil {
			continue // a slot out of use after a failed rebuild has no namespace
		}
		if listing, err := listTable(name); err == nil && listing == fc.slotRules {
			continue
		}
		if err := nft(name, insideRules(fc.cfg.Egress)); err != nil {
			slog.Error("rule table not restored", "table", name, "error", err)
		} else {
			slog.Warn("rule table restored", "table", name)
			fc.slotRules = relisted(name, fc.slotRules, insideRules(fc.cfg.Egress))
		}
	}
}

// relisted returns the expected listing again when a table that was just
// loaded still differs from it. That happens when nft was upgraded while the
// router ran and lists the same rules in another way; without it, Guard
// would load the table every 5 seconds.
func relisted(namespace, expected, rules string) string {
	if listing, err := listTable(namespace); err != nil || listing == expected {
		return expected
	}
	fresh, err := expectedListing(rules)
	if err != nil {
		slog.Error("rule table listing not renewed", "error", err)
		return expected
	}
	slog.Warn("rule table listing renewed: nft lists the same rules another way")
	return fresh
}

// prepareCgroup makes the parent cgroup whose children the jailer limits.
func prepareCgroup() error {
	parent := filepath.Join(cgroupRoot, cgroupParent)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	// The root usually delegates these already; only the parent must.
	_ = os.WriteFile(filepath.Join(cgroupRoot, "cgroup.subtree_control"), []byte("+memory +pids"), 0o644)
	if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+memory +pids"), 0o644); err != nil {
		return fmt.Errorf("enable memory and pids limits for %s: %w", parent, err)
	}
	return nil
}

func newSlot(name string, uid, gid, link int, egress Egress) (*slot, error) {
	_ = exec.Command("ip", "netns", "del", name).Run() // left over from an earlier run
	steps := [][]string{
		{"netns", "add", name},
		{"-n", name, "link", "set", "lo", "up"},
		// The slot's user owns the tap, so Firecracker opens it without any capability.
		{"-n", name, "tuntap", "add", "dev", "tap0", "mode", "tap", "user", strconv.Itoa(uid), "group", strconv.Itoa(gid)},
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
	if err := connect(name, link, egress); err != nil {
		return nil, err
	}
	ns, err := os.Open("/run/netns/" + name)
	if err != nil {
		return nil, err
	}
	return &slot{name: name, uid: uid, link: link, ns: ns}, nil
}

// Close removes the namespaces. Call it after every instance stopped.
func (fc *Firecracker) Close() {
	fc.mu.Lock()
	fc.closed = true
	fc.mu.Unlock()
	fc.recycling.Wait()
	for {
		select {
		case s := <-fc.slots:
			s.close()
			fc.netMu.Lock()
			_ = exec.Command("ip", "netns", "del", s.name).Run()
			fc.netMu.Unlock()
		default:
			return
		}
	}
}

// inNamespace runs do on a thread that is inside the slot's network
// namespace. Sockets created there stay in it.
func (s *slot) inNamespace(do func() error) error {
	runtime.LockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer original.Close()
	// The lock covers only the switch: after it the thread is inside the
	// namespace and needs the descriptor no more.
	s.mu.RLock()
	err = errors.New("the instance stopped")
	if !s.closed {
		err = unix.Setns(int(s.ns.Fd()), unix.CLONE_NEWNET)
	}
	s.mu.RUnlock()
	if err != nil {
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
	fc    *Firecracker
	slot  *slot
	port  int
	root  string // the jail's root directory on the host
	pidfd int
	api   *http.Client
	done  chan struct{}
	dead  sync.Once
	stop  sync.Once
}

// jail describes what one Firecracker process may see.
type jail struct {
	memoryMB int
	// files maps a path inside the jail to the host file it is a hard link of.
	files map[string]string
	// writable lets the process create files in /fn: only a build needs it.
	writable bool
}

func (fc *Firecracker) jailPath(name string) string {
	return filepath.Join(fc.cfg.JailBase, filepath.Base(fc.cfg.Firecracker), name)
}

// release cleans a slot and makes it free again. The network namespace is
// made new: the old one remembers the last instance's connections, and an
// outside host could send packets along them to the next instance. A slot
// that cannot be cleaned stays out of use: its next instance would share a
// user, a network namespace and a memory limit with whatever still runs
// there.
func (fc *Firecracker) release(s *slot) {
	if err := fc.cleanup(s.name); err != nil {
		slog.Error("slot taken out of use", "slot", s.name, "error", err)
		return
	}
	s.close()
	fc.mu.Lock()
	closed := fc.closed
	fc.mu.Unlock()
	if closed { // shutting down: remove the namespace, do not make a new one
		fc.netMu.Lock()
		_ = exec.Command("ip", "netns", "del", s.name).Run()
		fc.netMu.Unlock()
		return
	}
	var fresh *slot
	var err error
	for attempt := range 3 { // a failed rebuild is often a passing shortage
		fc.netMu.Lock()
		fresh, err = newSlot(s.name, s.uid, fc.cfg.GID, s.link, fc.cfg.Egress)
		fc.netMu.Unlock()
		if err == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	if err != nil {
		slog.Error("slot taken out of use", "slot", s.name, "error", err)
		return
	}
	fc.slots <- fresh
}

// start launches a jailed Firecracker in a free slot. The caller configures
// it through the API and must call Stop.
func (fc *Firecracker) start(ctx context.Context, logPath string, port int, j jail) (*vm, error) {
	var s *slot
	select {
	case s = <-fc.slots:
	default:
		return nil, ErrBusy
	}
	v, err := fc.launch(ctx, s, logPath, port, j)
	if err != nil {
		fc.release(s)
		return nil, err
	}
	return v, nil
}

func (fc *Firecracker) launch(ctx context.Context, s *slot, logPath string, port int, j jail) (*vm, error) {
	if err := fc.cleanup(s.name); err != nil { // whatever an earlier run left in this slot
		return nil, err
	}
	root := filepath.Join(fc.jailPath(s.name), "root")
	dir := filepath.Join(root, jailDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	owner := 0
	if j.writable {
		owner = s.uid
	}
	if err := os.Chown(dir, owner, fc.cfg.GID); err != nil {
		return nil, err
	}
	for inside, host := range j.files {
		if err := os.Link(host, filepath.Join(root, inside)); err != nil {
			return nil, fmt.Errorf("link %s into the jail: %w", host, err)
		}
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	// Not CommandContext: a jailer killed after it forked would leave a
	// Firecracker that nobody watches. The jailer ends by itself in milliseconds.
	cmd := exec.Command(fc.cfg.Jailer,
		"--id", s.name,
		"--exec-file", fc.cfg.Firecracker,
		"--uid", strconv.Itoa(s.uid),
		"--gid", strconv.Itoa(fc.cfg.GID),
		"--chroot-base-dir", fc.cfg.JailBase,
		"--netns", "/run/netns/"+s.name,
		"--new-pid-ns",
		"--cgroup-version", "2",
		"--parent-cgroup", cgroupParent,
		"--cgroup", "memory.max="+strconv.Itoa((j.memoryMB+overheadMB)<<20),
		"--cgroup", "memory.swap.max=0",
		"--cgroup", "pids.max="+strconv.Itoa(maxPIDs),
		"--", "--api-sock", jailSocket)
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// With a new PID namespace the jailer forks and ends: Firecracker is its
	// child, and the jailer leaves the child's PID in a file.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("jailer: %w", err)
	}
	pidFile := filepath.Join(root, filepath.Base(fc.cfg.Firecracker)+".pid")
	content, err := os.ReadFile(pidFile)
	if err != nil {
		return nil, fmt.Errorf("jailer left no PID: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || pid <= 1 {
		return nil, fmt.Errorf("jailer PID file: %q", content)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("firecracker ended at once: %w", err)
	}
	// The PID was read from a file. Make sure it still names this slot's
	// Firecracker and not a process that took the number after it ended.
	membership, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil || strings.TrimSpace(string(membership)) != "0::/"+cgroupParent+"/"+s.name {
		unix.Close(pidfd)
		return nil, fmt.Errorf("PID %d is not in this slot's cgroup", pid)
	}
	if err := ctx.Err(); err != nil {
		unix.Close(pidfd)
		return nil, err
	}
	v := &vm{fc: fc, slot: s, port: port, root: root, pidfd: pidfd, done: make(chan struct{})}
	sock := filepath.Join(root, jailSocket)
	v.api = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	go v.watch()
	// The socket file appears before Firecracker listens on it.
	err = retry(ctx, v.done, time.Millisecond, func() error {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			conn.Close()
		}
		return err
	})
	if err != nil {
		v.kill()
		return nil, fmt.Errorf("firecracker API: %w", err)
	}
	return v, nil
}

// watch closes done when the Firecracker process ends. It is not this
// process's child, so it is watched through its pidfd.
func (v *vm) watch() {
	fds := []unix.PollFd{{Fd: int32(v.pidfd), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(fds, -1)
		if err == nil || !errors.Is(err, unix.EINTR) {
			close(v.done)
			return
		}
	}
}

// kill ends the Firecracker process and returns when it is gone.
func (v *vm) kill() {
	v.dead.Do(func() {
		_ = unix.PidfdSendSignal(v.pidfd, unix.SIGKILL, nil, 0)
		<-v.done
		unix.Close(v.pidfd)
		v.api.CloseIdleConnections()
	})
}

// cleanup ends every process in a slot's cgroup, then removes the cgroup and
// the jail directory. An error means the slot is not safe to use.
func (fc *Firecracker) cleanup(name string) error {
	cgroup := filepath.Join(cgroupRoot, cgroupParent, name)
	if _, err := os.Stat(cgroup); err == nil {
		// cgroup.kill reaches a Firecracker that this process lost track of:
		// after a failed launch, a cancelled request or a daemon crash.
		_ = os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0o644)
		removed := false
		for range 1000 { // the kernel empties the cgroup shortly after the processes end
			err := os.Remove(cgroup)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				removed = true
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if !removed {
			return fmt.Errorf("cgroup %s still has processes", cgroup)
		}
	}
	// RemoveAll does not follow symbolic links, so a link the jailed user
	// left in its own directories is removed, not what it points at.
	return os.RemoveAll(fc.jailPath(name))
}

func (v *vm) Dial(ctx context.Context) (net.Conn, error) { return v.slot.dial(ctx, v.port) }
func (v *vm) Done() <-chan struct{}                      { return v.done }

func (v *vm) Stop() {
	v.stop.Do(func() {
		v.kill()
		// The answer does not wait for the slot to be made new. After
		// Close began, nothing waits for a goroutine, so clean up here.
		v.fc.mu.Lock()
		if v.fc.closed {
			v.fc.mu.Unlock()
			v.fc.release(v.slot)
			return
		}
		v.fc.recycling.Add(1)
		v.fc.mu.Unlock()
		go func() {
			defer v.fc.recycling.Done()
			v.fc.release(v.slot)
		}()
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
	v, err := fc.start(ctx, filepath.Join(filepath.Dir(filepath.Dir(f.Dir)), "log"), f.Port, jail{
		memoryMB: f.MemoryMB,
		files: map[string]string{
			jailRootfs: filepath.Join(f.Dir, "rootfs.ext4"),
			jailState:  filepath.Join(f.Dir, "snap.state"),
			jailMemory: filepath.Join(f.Dir, "snap.mem"),
		},
	})
	if err != nil {
		return nil, err
	}
	err = v.call(ctx, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": jailState,
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": jailMemory},
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

// protect makes a function file readable by the jails' group and writable
// by nobody: every instance of a function shares these files.
func (fc *Firecracker) protect(path string) error {
	if err := os.Chown(path, 0, fc.cfg.GID); err != nil {
		return err
	}
	return os.Chmod(path, 0o440)
}

// snapshot cold-boots a root file system, waits until the function answers
// and writes snap.state and snap.mem next to it.
func (fc *Firecracker) snapshot(ctx context.Context, f Function, logPath string) error {
	rootfs := filepath.Join(f.Dir, "rootfs.ext4")
	if err := fc.protect(rootfs); err != nil {
		return err
	}
	v, err := fc.start(ctx, logPath, f.Port, jail{
		memoryMB: f.MemoryMB,
		files:    map[string]string{jailRootfs: rootfs, jailKernel: fc.cfg.Kernel},
		writable: true,
	})
	if err != nil {
		return err
	}
	defer v.Stop()
	steps := []struct {
		path string
		body any
	}{
		{"/boot-source", map[string]string{"kernel_image_path": jailKernel, "boot_args": bootArgs}},
		{"/drives/rootfs", map[string]any{
			"drive_id": "rootfs", "path_on_host": jailRootfs, "is_root_device": true, "is_read_only": true,
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
	err = v.call(ctx, http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_type": "Full", "snapshot_path": jailState, "mem_file_path": jailMemory,
	})
	if err != nil {
		return err
	}
	// The jailed process wrote these as its own user. End it first, so it
	// holds no open file, then copy them out of the jail.
	v.kill()
	limit := int64(f.MemoryMB+16) << 20
	for _, name := range []string{"snap.state", "snap.mem"} {
		if err := fc.collect(v, name, filepath.Join(f.Dir, name), limit); err != nil {
			return fmt.Errorf("collect %s: %w", name, err)
		}
	}
	return nil
}

// collect copies a file the jailed process wrote into a new file that root
// owns. The jailed user owns the jail's root and /fn during a build, so it
// could have replaced any name there with a symbolic link or a hard link to
// something else. Nothing here trusts a path it could write: the jail is
// opened by descriptor, links are refused at every step, and the file must
// be a regular file of that user with one name.
func (fc *Firecracker) collect(v *vm, name, target string, limit int64) error {
	jailRoot, err := unix.Open(v.root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(jailRoot)
	fd, err := unix.Openat2(jailRoot, strings.TrimPrefix(jailDir, "/")+"/"+name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), name)
	defer source.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	switch {
	case stat.Mode&unix.S_IFMT != unix.S_IFREG:
		return errors.New("not a regular file")
	case stat.Nlink != 1:
		return errors.New("the file has more than one name")
	case int(stat.Uid) != v.slot.uid:
		return errors.New("the file is not owned by the instance's user")
	case stat.Size > limit:
		return fmt.Errorf("%d bytes, more than the function's memory", stat.Size)
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o440)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(source, limit))
	if err == nil {
		err = out.Chown(0, fc.cfg.GID)
	}
	if err == nil {
		err = out.Chmod(0o440) // the mode at creation is cut by the umask
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(target)
	}
	return err
}
