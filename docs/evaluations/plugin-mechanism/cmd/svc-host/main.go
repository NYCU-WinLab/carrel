// svc-host is the agent side when plugins are services: it dials a unix
// socket and checks the plugin's contract before it uses it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpb"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/hostcli"
)

func main() {
	socket := flag.String("socket", "/run/carrel-plugins/snapshot.sock", "unix socket")
	min := flag.Uint("min-contract", 1, "oldest contract this host serves")
	max := flag.Uint("max-contract", 2, "newest contract this host serves")
	flag.Parse()
	if err := run(*socket, uint32(*min), uint32(*max), flag.Args()); err != nil {
		hostcli.Emit(os.Stdout, "error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
}

func run(socket string, min, max uint32, args []string) error {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pluginpb.NewPluginClient(conn)
	// The plugin may be restarting: ask again for up to 10 s.
	var d *pluginpb.DescribeResponse
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		d, err = c.Describe(ctx, &pluginpb.DescribeRequest{})
		cancel()
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("plugin: %w", err)
	}
	if d.Contract < min || d.Contract > max {
		return fmt.Errorf("plugin %s %s speaks contract %d; this host serves contracts %d to %d: install a plugin release built for one of them",
			d.Name, d.Version, d.Contract, min, max)
	}
	hostcli.Emit(os.Stdout, "plugin", map[string]any{"name": d.Name, "version": d.Version, "contract": d.Contract})
	return hostcli.Run(context.Background(), c, args, os.Stdout)
}
