// svc-plugin is the snapshot plugin as its own service on a unix socket,
// contract 1. A supervisor (systemd in production) starts and restarts it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpbv1"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/rpcv1"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/snapshot"
)

func main() {
	socket := flag.String("socket", "/run/carrel-plugins/snapshot.sock", "unix socket")
	state := flag.String("state", "/tmp/snapshot-plugin", "state directory")
	flag.Parse()
	_ = os.Remove(*socket)
	l, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	pluginpbv1.RegisterPluginServer(s, &rpcv1.Server{P: &snapshot.Plugin{Dir: *state}})
	b, _ := json.Marshal(map[string]any{"event": "listening", "pid": os.Getpid(), "contract": rpcv1.Contract})
	fmt.Println(string(b))
	log.Fatal(s.Serve(l))
}
