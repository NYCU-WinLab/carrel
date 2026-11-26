// Package rpc serves the snapshot plugin over contract 2.
package rpc

import (
	"context"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpb"
	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/snapshot"
)

const Contract = 2

type Server struct {
	pluginpb.UnimplementedPluginServer
	P *snapshot.Plugin
}

func op(o snapshot.Op, err error) (*pluginpb.Operation, error) {
	if err != nil {
		return nil, err
	}
	return &pluginpb.Operation{IdempotencyKey: o.Key, State: o.State, Done: o.Done, Progress: o.Progress,
		Result: o.Result, Error: o.Error, Task: o.Task, Message: o.Message}, nil
}

func (s *Server) Describe(context.Context, *pluginpb.DescribeRequest) (*pluginpb.DescribeResponse, error) {
	return &pluginpb.DescribeResponse{Name: snapshot.Name, Version: snapshot.Version, Contract: Contract,
		Operations: []*pluginpb.OperationType{{Name: snapshot.Name, ParamsSchema: snapshot.Schema}}}, nil
}

func (s *Server) Probe(context.Context, *pluginpb.ProbeRequest) (*pluginpb.ProbeResponse, error) {
	ok, why := s.P.Probe()
	return &pluginpb.ProbeResponse{Supported: ok, Reason: why}, nil
}

func (s *Server) StartOperation(_ context.Context, r *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	return op(s.P.Start(r.IdempotencyKey, r.Operation, r.Params))
}

func (s *Server) GetOperation(_ context.Context, r *pluginpb.GetRequest) (*pluginpb.Operation, error) {
	return op(s.P.Get(r.IdempotencyKey))
}

func (s *Server) Cancel(_ context.Context, r *pluginpb.CancelRequest) (*pluginpb.Operation, error) {
	return op(s.P.Cancel(r.IdempotencyKey))
}
