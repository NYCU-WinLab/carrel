// Package gp is the go-plugin glue. It imports no generated contract, so a
// contract 1 plugin and a contract 2 host each link only their own.
package gp

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

var Handshake = plugin.HandshakeConfig{MagicCookieKey: "CARREL_PLUGIN", MagicCookieValue: "spike-563"}

// Plugin registers a contract server in the plugin, and hands the host the
// connection to wrap in its own client.
type Plugin struct {
	plugin.NetRPCUnsupportedPlugin
	Register func(*grpc.Server)
}

func (p *Plugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	p.Register(s)
	return nil
}

func (p *Plugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return c, nil
}
