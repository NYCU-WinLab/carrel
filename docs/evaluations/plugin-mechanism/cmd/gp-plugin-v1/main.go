// gp-plugin is the snapshot plugin under hashicorp/go-plugin, contract 1.
package main

import (
	"flag"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpbv1"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gp"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/rpcv1"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/snapshot"
)

func main() {
	state := flag.String("state", "/tmp/snapshot-plugin", "state directory")
	flag.Parse()
	p := &snapshot.Plugin{Dir: *state}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: gp.Handshake,
		VersionedPlugins: map[int]plugin.PluginSet{rpcv1.Contract: {"snapshot": &gp.Plugin{Register: func(s *grpc.Server) {
			pluginpbv1.RegisterPluginServer(s, &rpcv1.Server{P: p})
		}}}},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
