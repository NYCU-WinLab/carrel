// Package schedule is a function's cron schedule (#643): the control plane
// checks it, and the function host fires it.
package schedule

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	// Hosts and the control plane read zones without a system database.
	_ "time/tzdata"
)

const (
	MaxBody = 64 << 10
	// MaxPerFunction bounds a function's schedules.
	MaxPerFunction = 10
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Schedule runs a request to a function: at every minute its cron
// expression matches in its time zone, the host sends GET Path (POST with
// Body when there is one) through its router.
type Schedule struct {
	Name     string `json:"name"`
	Cron     string `json:"cron"`
	TimeZone string `json:"time_zone"`
	Path     string `json:"path"`
	Body     string `json:"body,omitempty"`
}

// Check reports what is wrong with s, in words a member can act on.
func (s Schedule) Check() error {
	if !nameRE.MatchString(s.Name) {
		return errors.New("name must be lower-case letters, digits and dashes, starting with a letter")
	}
	if _, err := Parse(s.Cron); err != nil {
		return err
	}
	if _, err := time.LoadLocation(s.TimeZone); err != nil || s.TimeZone == "" || s.TimeZone == "Local" {
		return fmt.Errorf("time_zone %q is not an IANA zone such as UTC or Asia/Taipei", s.TimeZone)
	}
	if !strings.HasPrefix(s.Path, "/") || strings.HasPrefix(s.Path, "//") || strings.ContainsAny(s.Path, " \t\r\n#") || len(s.Path) > 1024 {
		return errors.New("path must start with a single / and hold no spaces or #")
	}
	if len(s.Body) > MaxBody {
		return errors.New("body is at most 64 KiB")
	}
	return nil
}

// Due tells whether s fires in the minute that starts at t.
func (s Schedule) Due(t time.Time) bool {
	c, err := Parse(s.Cron)
	if err != nil {
		return false
	}
	loc, err := time.LoadLocation(s.TimeZone)
	if err != nil {
		return false
	}
	return c.Matches(t.In(loc))
}

// Cron is a 5-field cron expression: minute, hour, day of month, month and
// day of week (0 to 7, both 0 and 7 are Sunday).
type Cron struct {
	minute, hour, dom, month, dow uint64
	domAny, dowAny                bool
}

var fields = []struct {
	name     string
	min, max int
}{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}

// Parse reads an expression such as "*/5 * * * *" or "0 9 * * 1-5".
func Parse(expr string) (Cron, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return Cron{}, errors.New("cron needs 5 fields: minute hour day-of-month month day-of-week")
	}
	var sets [5]uint64
	for i, part := range parts {
		set, err := field(part, fields[i].min, fields[i].max)
		if err != nil {
			return Cron{}, fmt.Errorf("cron %s field %q: %w", fields[i].name, part, err)
		}
		sets[i] = set
	}
	// Sunday is 0 and 7.
	if sets[4]&(1<<7) != 0 {
		sets[4] |= 1
	}
	return Cron{minute: sets[0], hour: sets[1], dom: sets[2], month: sets[3], dow: sets[4], domAny: parts[2] == "*", dowAny: parts[4] == "*"}, nil
}

// field reads a comma list of *, n, a-b, each with an optional /step.
func field(s string, lo, hi int) (uint64, error) {
	var set uint64
	for _, item := range strings.Split(s, ",") {
		rng, step := item, 1
		if r, st, ok := strings.Cut(item, "/"); ok {
			n, err := strconv.Atoi(st)
			if err != nil || n < 1 || n > hi {
				return 0, errors.New("the step must be a number from 1")
			}
			rng, step = r, n
		}
		from, to := lo, hi
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			x, ex := strconv.Atoi(a)
			y, ey := strconv.Atoi(b)
			if ex != nil || ey != nil || x > y {
				return 0, errors.New("a range is two numbers, low-high")
			}
			from, to = x, y
		default:
			x, err := strconv.Atoi(rng)
			if err != nil {
				return 0, errors.New("use numbers, *, ranges and steps; names are not supported")
			}
			from, to = x, x
			if strings.Contains(item, "/") {
				to = hi
			}
		}
		if from < lo || to > hi {
			return 0, fmt.Errorf("values run from %d to %d", lo, hi)
		}
		for v := from; v <= to; v += step {
			set |= 1 << v
		}
	}
	return set, nil
}

// Matches tells whether the minute of t is in the schedule. As in cron,
// when both day fields are restricted, either one matching is enough.
func (c Cron) Matches(t time.Time) bool {
	if c.minute&(1<<t.Minute()) == 0 || c.hour&(1<<t.Hour()) == 0 || c.month&(1<<int(t.Month())) == 0 {
		return false
	}
	dom := c.dom&(1<<t.Day()) != 0
	dow := c.dow&(1<<int(t.Weekday())) != 0
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow
}
