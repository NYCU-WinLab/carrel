package fn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// A function's output reaches the control plane only when a member asks for
// it (function_logs): the agent waits for requests next to the state poll,
// reads the tail of the log on this host and posts it back. Nothing is kept
// anywhere but the host's capped log files.

const (
	// stampLayout starts every line of a log. Its fixed width lets a reader
	// find the time without parsing the line.
	stampLayout = "2006-01-02T15:04:05.000Z07:00"
	stampWidth  = len("2006-01-02T15:04:05.000Z")
	// MaxLogBytes bounds one answer.
	MaxLogBytes = 1 << 20
)

// LogRequest asks for the tail of one function's log.
type LogRequest struct {
	ID       string `json:"id"`
	Function string `json:"function"`
	// Build reads the log of the builds instead of the instances' output.
	Build bool `json:"build"`
	// Since keeps only lines stamped at or after this Unix time, when set.
	Since    int64 `json:"since"`
	MaxBytes int   `json:"max_bytes"`
}

// LogAnswer is the agent's reply to one LogRequest.
type LogAnswer struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

// stamp puts the time at the start of every line that begins in p. atStart
// says whether the previous write ended a line, and is updated.
func stamp(p []byte, at time.Time, atStart *bool) []byte {
	prefix := []byte(at.UTC().Format(stampLayout) + " ")
	out := make([]byte, 0, len(p)+len(prefix))
	for len(p) > 0 {
		if *atStart {
			out = append(out, prefix...)
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			out = append(out, p...)
			*atStart = false
			break
		}
		out = append(out, p[:i+1]...)
		p = p[i+1:]
		*atStart = true
	}
	return out
}

// ReadLog returns the tail of a function's log under root: the older half
// first, then the current one. It opens files only beneath root without
// following links, so nothing a function controls can point it elsewhere.
func ReadLog(root string, req LogRequest) (LogAnswer, error) {
	answer := LogAnswer{ID: req.ID}
	if !nameRE.MatchString(req.Function) {
		return answer, errors.New("invalid function")
	}
	limit := req.MaxBytes
	if limit <= 0 || limit > MaxLogBytes {
		limit = MaxLogBytes
	}
	name := "log"
	if req.Build {
		name = "build.log"
	}
	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return answer, err
	}
	defer unix.Close(dir)
	var content []byte
	for _, file := range []string{name + ".1", name} {
		part, err := readBeneath(dir, filepath.Join(req.Function, file))
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return answer, err
		}
		content = append(content, part...)
	}
	if req.Since > 0 {
		content = linesSince(content, time.Unix(req.Since, 0))
	}
	if len(content) > limit {
		content = content[len(content)-limit:]
		// Start at a whole line when one begins within the kept part.
		if i := bytes.IndexByte(content, '\n'); i >= 0 && i+1 < len(content) {
			content = content[i+1:]
		}
		answer.Truncated = true
	}
	answer.Text = string(bytes.ToValidUTF8(content, []byte("�")))
	return answer, nil
}

// readBeneath reads a regular file below dir, at most two log halves long.
func readBeneath(dir int, path string) ([]byte, error) {
	fd, err := unix.Openat2(dir, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(file, 2*logHalf))
}

// linesSince drops the lines stamped before since. A line without a stamp
// belongs with the line before it.
func linesSince(content []byte, since time.Time) []byte {
	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], '\n')
		if end < 0 {
			end = len(content)
		} else {
			end += start + 1
		}
		if len(content)-start >= stampWidth {
			if at, err := time.Parse(stampLayout, string(content[start:start+stampWidth])); err == nil && !at.Before(since) {
				return content[start:]
			}
		}
		start = end
	}
	return nil
}

// serveLogs answers the control plane's log requests until ctx ends.
func (a *Agent) serveLogs(ctx context.Context) {
	for ctx.Err() == nil {
		var asked struct {
			Requests []LogRequest `json:"requests"`
		}
		start := time.Now()
		poll, cancel := context.WithTimeout(ctx, agentPoll+15*time.Second)
		err := a.call(poll, "GET", "/functions/v1/agent/logs", nil, &asked)
		cancel()
		if err == nil && len(asked.Requests) == 0 && time.Since(start) < time.Second {
			// The control plane holds an empty poll open; one that does not
			// must not turn this loop into a flood.
			err = errors.New("the log poll answered at once with no request")
		}
		for _, req := range asked.Requests {
			if err != nil {
				break
			}
			answer, rerr := ReadLog(a.Root, req)
			if rerr != nil {
				answer = LogAnswer{ID: req.ID, Error: rerr.Error()}
			}
			err = a.call(ctx, "POST", "/functions/v1/agent/logs", answer, nil)
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("function host logs", "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(agentRetry):
			}
		}
	}
}
