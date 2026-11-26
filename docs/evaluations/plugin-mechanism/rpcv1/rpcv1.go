// Package rpcv1 serves the snapshot plugin over contract 1, as a plugin
// built before Operation.message would.
package rpcv1

import (
	"context"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpbv1"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/snapshot"
)

const Contract = 1

type Server struct {
	pluginpbv1.UnimplementedPluginServer
	P *snapshot.Plugin
}

func op(o snapshot.Op, err error) (*pluginpbv1.Operation, error) {
	if err != nil {
		return nil, err
	}
	return &pluginpbv1.Operation{IdempotencyKey: o.Key, State: o.State, Done: o.Done, Progress: o.Progress,
		Result: o.Result, Error: o.Error, Task: o.Task}, nil
}

func (s *Server) Describe(context.Context, *pluginpbv1.DescribeRequest) (*pluginpbv1.DescribeResponse, error) {
	return &pluginpbv1.DescribeResponse{Name: snapshot.Name, Version: snapshot.Version, Contract: Contract,
		Operations: []*pluginpbv1.OperationType{{Name: snapshot.Name, ParamsSchema: snapshot.Schema}}}, nil
}

func (s *Server) Probe(context.Context, *pluginpbv1.ProbeRequest) (*pluginpbv1.ProbeResponse, error) {
	ok, why := s.P.Probe()
	return &pluginpbv1.ProbeResponse{Supported: ok, Reason: why}, nil
}

func (s *Server) StartOperation(_ context.Context, r *pluginpbv1.StartRequest) (*pluginpbv1.Operation, error) {
	return op(s.P.Start(r.IdempotencyKey, r.Operation, r.Params))
}

func (s *Server) GetOperation(_ context.Context, r *pluginpbv1.GetRequest) (*pluginpbv1.Operation, error) {
	return op(s.P.Get(r.IdempotencyKey))
}

func (s *Server) Cancel(_ context.Context, r *pluginpbv1.CancelRequest) (*pluginpbv1.Operation, error) {
	return op(s.P.Cancel(r.IdempotencyKey))
}
