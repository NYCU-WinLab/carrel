// Command freeze serves the freeze plugin on the socket systemd passes as
// fd 3, or on -socket for a test run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"google.golang.org/grpc"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
	"github.com/NYCU-WinLab/carrel/plugins/freeze"
)

// version is set at build time.
var version = ""

func listener(path string) (net.Listener, error) {
	if path != "" {
		return net.Listen("unix", path)
	}
	if os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, errors.New("no socket from systemd (LISTEN_FDS=1) and no -socket")
	}
	return net.FileListener(os.NewFile(3, "carrel-plugin-freeze.socket"))
}

func main() {
	socket := flag.String("socket", "", "listen on this unix socket instead of fd 3")
	flag.Parse()
	if version != "" {
		freeze.Version = version
	}
	l, err := listener(*socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := freeze.NewServer()
	if problem := freeze.Problem(s); problem != "" {
		slog.Warn("freeze_plugin_unsupported", "reason", problem)
	}
	g := grpc.NewServer()
	pluginpb.RegisterPluginServer(g, s)
	if err := g.Serve(l); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
