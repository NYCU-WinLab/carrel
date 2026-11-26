// gp-plugin is the snapshot plugin under hashicorp/go-plugin, contract 2.
package main

import (
	"flag"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpb"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gp"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/rpc"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/snapshot"
)

func main() {
	state := flag.String("state", "/tmp/snapshot-plugin", "state directory")
	flag.Parse()
	p := &snapshot.Plugin{Dir: *state}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: gp.Handshake,
		VersionedPlugins: map[int]plugin.PluginSet{rpc.Contract: {"snapshot": &gp.Plugin{Register: func(s *grpc.Server) {
			pluginpb.RegisterPluginServer(s, &rpc.Server{P: p})
		}}}},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
