//go:build linux

// carrel-fn-init is process 1 inside a function's microVM (PLAN 7.11). It
// puts a writable overlay over the read-only image, brings up the network,
// starts the image's command and answers the host's control calls.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// spec is written into the image by the builder as /.fn/spec.json.
type spec struct {
	Cmd  []string `json:"cmd"`
	Env  []string `json:"env"`
	Cwd  string   `json:"cwd"`
	Port int      `json:"port"`
}

const (
	guestAddr   = "172.16.0.2"
	hostAddr    = "172.16.0.1"
	controlPort = 1
)

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "carrel-fn-init runs only as process 1 of a function microVM")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "carrel-fn-init:", err)
	}
	// Process 1 must not return: the kernel would panic. Power off instead,
	// which ends the microVM and tells the host the function stopped.
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}

func run() error {
	content, err := os.ReadFile("/.fn/spec.json")
	if err != nil {
		return err
	}
	var s spec
	if err := json.Unmarshal(content, &s); err != nil || len(s.Cmd) == 0 {
		return errors.New("invalid /.fn/spec.json")
	}
	if err := overlayRoot(); err != nil {
		return fmt.Errorf("overlay: %w", err)
	}
	mounts()
	if err := network(); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	go control()

	// The command is looked up in the image's PATH, so the image's
	// environment becomes this process's environment first.
	for _, pair := range append([]string{"HOME=/root", "PORT=" + strconv.Itoa(s.Port)}, s.Env...) {
		if key, value, ok := strings.Cut(pair, "="); ok {
			_ = os.Setenv(key, value)
		}
	}
	cmd := exec.Command(s.Cmd[0], s.Cmd[1:]...)
	cmd.Dir = s.Cwd
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %q: %w", s.Cmd[0], err)
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, unix.SIGTERM, unix.SIGINT)
	go func() {
		for sig := range signals {
			_ = cmd.Process.Signal(sig)
		}
	}()
	// Reap every child, as process 1 must, until the function's own command ends.
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if pid == cmd.Process.Pid {
			return fmt.Errorf("function command ended: exit %d", status.ExitStatus())
		}
	}
}

// overlayRoot makes the root writable without touching the image: writes go
// to memory and are gone when the microVM stops.
func overlayRoot() error {
	if err := unix.Mount("tmpfs", "/.fn/rw", "tmpfs", 0, "mode=0755"); err != nil {
		return err
	}
	for _, dir := range []string{"/.fn/rw/upper", "/.fn/rw/work"} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
	}
	options := "lowerdir=/,upperdir=/.fn/rw/upper,workdir=/.fn/rw/work"
	if err := unix.Mount("overlay", "/.fn/newroot", "overlay", 0, options); err != nil {
		return err
	}
	if err := unix.Chdir("/.fn/newroot"); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", ".fn/old"); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return unix.Unmount("/.fn/old", unix.MNT_DETACH)
}

func mounts() {
	type mount struct{ source, target, kind, data string }
	for _, m := range []mount{
		{"proc", "/proc", "proc", ""},
		{"sysfs", "/sys", "sysfs", ""},
		{"devtmpfs", "/dev", "devtmpfs", ""},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777"},
		{"tmpfs", "/run", "tmpfs", "mode=0755"},
	} {
		_ = os.MkdirAll(m.target, 0o755)
		_ = unix.Mount(m.source, m.target, m.kind, 0, m.data)
	}
	_ = os.MkdirAll("/dev/pts", 0o755)
	_ = unix.Mount("devpts", "/dev/pts", "devpts", 0, "")
	_ = os.MkdirAll("/dev/shm", 0o1777)
	_ = unix.Mount("tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777")
}

// network gives eth0 the one address every function has. Each microVM sits
// alone in its own network namespace on the host, so the address never clashes.
func network() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := linkUp(fd, "lo"); err != nil {
		return err
	}
	if err := setAddr(fd, "eth0", unix.SIOCSIFADDR, guestAddr); err != nil {
		return err
	}
	if err := setAddr(fd, "eth0", unix.SIOCSIFNETMASK, "255.255.255.252"); err != nil {
		return err
	}
	if err := linkUp(fd, "eth0"); err != nil {
		return err
	}
	return defaultRoute(fd, hostAddr)
}

type ifreqAddr struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
	_    [8]byte
}

type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte
}

func inet4(address string) unix.RawSockaddrInet4 {
	raw := unix.RawSockaddrInet4{Family: unix.AF_INET}
	copy(raw.Addr[:], net.ParseIP(address).To4())
	return raw
}

func ioctl(fd int, request uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

func setAddr(fd int, name string, request uint, address string) error {
	req := ifreqAddr{addr: inet4(address)}
	copy(req.name[:], name)
	return ioctl(fd, request, unsafe.Pointer(&req))
}

func linkUp(fd int, name string) error {
	req := ifreqFlags{}
	copy(req.name[:], name)
	if err := ioctl(fd, unix.SIOCGIFFLAGS, unsafe.Pointer(&req)); err != nil {
		return err
	}
	req.flags |= unix.IFF_UP | unix.IFF_RUNNING
	return ioctl(fd, unix.SIOCSIFFLAGS, unsafe.Pointer(&req))
}

// rtentry is the kernel's struct rtentry for x86-64.
type rtentry struct {
	_       uint64
	dst     unix.RawSockaddrInet4
	gateway unix.RawSockaddrInet4
	genmask unix.RawSockaddrInet4
	flags   uint16
	_       [14]byte
	_       [64]byte
}

func defaultRoute(fd int, gateway string) error {
	route := rtentry{
		dst:     unix.RawSockaddrInet4{Family: unix.AF_INET},
		gateway: inet4(gateway),
		genmask: unix.RawSockaddrInet4{Family: unix.AF_INET},
		flags:   unix.RTF_UP | unix.RTF_GATEWAY,
	}
	return ioctl(fd, unix.SIOCADDRT, unsafe.Pointer(&route))
}

// control answers the host on a port no image uses. A restored guest reads
// the time of its snapshot, so the host sends the current time on every wake.
func control() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /clock", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64))
		nanos, parseErr := strconv.ParseInt(string(body), 10, 64)
		if err != nil || parseErr != nil || nanos <= 0 {
			http.Error(w, "body must be Unix time in nanoseconds", http.StatusBadRequest)
			return
		}
		ts := unix.NsecToTimespec(nanos)
		if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{
		Addr:              net.JoinHostPort(guestAddr, strconv.Itoa(controlPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	for {
		_ = server.ListenAndServe()
		time.Sleep(100 * time.Millisecond)
	}
}
