// gp-host is the agent side under hashicorp/go-plugin: it launches the
// plugin as its child, or reattaches to one a previous host left running.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpb"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gp"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/hostcli"
)

// reattach is plugin.ReattachConfig in a form JSON keeps.
type reattach struct {
	Protocol        string `json:"protocol"`
	ProtocolVersion int    `json:"protocol_version"`
	Network         string `json:"network"`
	Addr            string `json:"addr"`
	Pid             int    `json:"pid"`
}

func main() {
	path := flag.String("plugin", "", "plugin executable, with its arguments after a space")
	versions := flag.String("versions", "1,2", "contract versions this host serves")
	file := flag.String("reattach", "", "keep the plugin running and reattach to it through this file")
	flag.Parse()
	if err := run(*path, *versions, *file, flag.Args()); err != nil {
		hostcli.Emit(os.Stdout, "error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
}

func run(path, versions, file string, args []string) error {
	set := map[int]plugin.PluginSet{}
	for _, v := range strings.Split(versions, ",") {
		n, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		set[n] = plugin.PluginSet{"snapshot": &gp.Plugin{}}
	}
	cfg := &plugin.ClientConfig{HandshakeConfig: gp.Handshake, VersionedPlugins: set,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           hclog.New(&hclog.LoggerOptions{Level: hclog.Error, Output: os.Stderr})}
	var saved reattach
	if b, err := os.ReadFile(file); file != "" && err == nil && json.Unmarshal(b, &saved) == nil {
		var addr net.Addr
		if saved.Network == "unix" {
			addr = &net.UnixAddr{Name: saved.Addr, Net: "unix"}
		} else {
			addr, _ = net.ResolveTCPAddr(saved.Network, saved.Addr)
		}
		cfg.Reattach = &plugin.ReattachConfig{Protocol: plugin.Protocol(saved.Protocol),
			ProtocolVersion: saved.ProtocolVersion, Addr: addr, Pid: saved.Pid}
		// Reattaching skips the version negotiation, and with it the choice
		// of plugin set: name the set of the saved version here.
		if _, ok := set[saved.ProtocolVersion]; !ok {
			return fmt.Errorf("the running plugin speaks contract %d, which this host does not serve", saved.ProtocolVersion)
		}
		cfg.Plugins = set[saved.ProtocolVersion]
	} else {
		parts := strings.Fields(path)
		if len(parts) == 0 {
			return errors.New("-plugin is required")
		}
		cfg.Cmd = exec.Command(parts[0], parts[1:]...)
	}
	client := plugin.NewClient(cfg)
	if file == "" {
		defer client.Kill()
	}
	rpc, err := client.Client()
	if err != nil {
		return fmt.Errorf("plugin: %w", err)
	}
	raw, err := rpc.Dispense("snapshot")
	if err != nil {
		return fmt.Errorf("dispense: %w", err)
	}
	r := client.ReattachConfig()
	version := client.NegotiatedVersion()
	if cfg.Reattach != nil {
		version = saved.ProtocolVersion
	}
	hostcli.Emit(os.Stdout, "plugin", map[string]any{"pid": r.Pid, "version": version,
		"reattached": cfg.Reattach != nil})
	if file != "" {
		// ReattachConfig leaves ProtocolVersion at 0 when the version was
		// negotiated from VersionedPlugins: keep the negotiated one.
		b, _ := json.Marshal(reattach{Protocol: string(r.Protocol), ProtocolVersion: version,
			Network: r.Addr.Network(), Addr: r.Addr.String(), Pid: r.Pid})
		if err := os.WriteFile(file, b, 0o600); err != nil {
			return err
		}
	}
	return hostcli.Run(context.Background(), pluginpb.NewPluginClient(raw.(*grpc.ClientConn)), args, os.Stdout)
}
