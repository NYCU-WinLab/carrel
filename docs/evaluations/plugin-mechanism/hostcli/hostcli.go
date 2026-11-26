// Package hostcli is the host side both prototypes share: it starts,
// watches, reads or cancels one operation and prints JSON lines.
package hostcli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen/pluginpb"
)

func Emit(w io.Writer, event string, v map[string]any) {
	v["event"] = event
	v["at"] = time.Now().UnixMilli()
	b, _ := json.Marshal(v)
	fmt.Fprintln(w, string(b))
}

func emitOp(w io.Writer, o *pluginpb.Operation) {
	Emit(w, "op", map[string]any{"key": o.IdempotencyKey, "state": o.State, "done": o.Done,
		"progress": o.Progress, "task": o.Task, "message": o.Message, "error": o.Error, "result": o.Result})
}

// Run: start KEY SECONDS | watch KEY | get KEY | cancel KEY | describe.
func Run(ctx context.Context, c pluginpb.PluginClient, args []string, w io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: start KEY SECONDS | watch KEY | get KEY | cancel KEY | describe")
	}
	switch args[0] {
	case "describe":
		d, err := c.Describe(ctx, &pluginpb.DescribeRequest{})
		if err != nil {
			return err
		}
		Emit(w, "describe", map[string]any{"name": d.Name, "version": d.Version, "contract": d.Contract})
		return nil
	case "start":
		o, err := c.StartOperation(ctx, &pluginpb.StartRequest{IdempotencyKey: args[1], Operation: "snapshot",
			Params: fmt.Sprintf(`{"seconds":%s}`, args[2])})
		if err != nil {
			return err
		}
		emitOp(w, o)
		return watch(ctx, c, args[1], w)
	case "watch":
		return watch(ctx, c, args[1], w)
	case "get":
		o, err := c.GetOperation(ctx, &pluginpb.GetRequest{IdempotencyKey: args[1]})
		if err != nil {
			return err
		}
		emitOp(w, o)
		return nil
	case "cancel":
		o, err := c.Cancel(ctx, &pluginpb.CancelRequest{IdempotencyKey: args[1]})
		if err != nil {
			return err
		}
		emitOp(w, o)
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// watch reads the operation every 200 ms until it is done. A failed read is
// reported and retried, so a plugin that comes back is picked up again.
func watch(ctx context.Context, c pluginpb.PluginClient, key string, w io.Writer) error {
	for {
		o, err := c.GetOperation(ctx, &pluginpb.GetRequest{IdempotencyKey: key})
		if err != nil {
			Emit(w, "get_failed", map[string]any{"key": key, "error": err.Error()})
		} else {
			emitOp(w, o)
			if o.Done {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
