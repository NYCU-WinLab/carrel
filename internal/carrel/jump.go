package carrel

import (
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The SSH jump host (issue #98) lets a member reach machines that have no
// public port: `ssh -J jump@<origin> user@<machine address>`. It runs in CT 102
// as a forwarder only. Each saved or installed public key may open port 22 of
// the machines in the tenants that hold it, and nothing else; the session
// itself stays end to end between the member and the machine.

var jumpKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}`)

// jumpAuthorizedKeys renders the jump user's authorized_keys file.
func jumpAuthorizedKeys(s *Store) string {
	reach := map[string]map[string]bool{}
	for _, t := range s.Tenants() {
		if t["status"] != "active" {
			continue
		}
		n := integer(t["n"])
		machines := filter(s.Objects("machines", n), func(m D) bool { return m["state"] != "deleting" })
		keys := map[string]bool{}
		for _, k := range rowsOf[sshKey](s, "keys", n) {
			keys[k.Key] = true
		}
		for _, m := range machines {
			for _, k := range arr(m["ssh_keys"]) {
				keys[str(k)] = true
			}
		}
		for k := range keys {
			// Type and key only: a comment never reaches the options line.
			key := jumpKey.FindString(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			if reach[key] == nil {
				reach[key] = map[string]bool{}
			}
			for _, m := range machines {
				// A machine without SSH forwards its declared ports (#94).
				ports := servicePortsOf(m)
				if len(ports) == 0 {
					ports = []int{22}
				}
				for _, p := range ports {
					reach[key][fmt.Sprintf("%s:%d", str(m["ip"]), p)] = true
				}
			}
		}
	}
	keys := make([]string, 0, len(reach))
	for k := range reach {
		if len(reach[k]) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		targets := make([]string, 0, len(reach[k]))
		for t := range reach[k] {
			targets = append(targets, fmt.Sprintf("permitopen=%q", t))
		}
		sort.Strings(targets)
		fmt.Fprintf(&b, "restrict,port-forwarding,command=\"/usr/sbin/nologin\",%s %s\n", strings.Join(targets, ","), k)
	}
	return b.String()
}

func (e *Execution) jumpEnabled() bool { return e.P.Config.SSHJump }

// maxSavedKeys bounds ssh_key_add, which also keeps the jump file small.
const maxSavedKeys = 50

// jumpCertificates maps each principal a lab certificate may carry to the
// SSH address of every machine whose principals file names it: the creator
// or project:<name>, then the machine_access grants. On the jump host,
// jump-cert.py joins the addresses of all the principals in one certificate
// into a single line, because sshd uses only the first line that matches.
// Only machines that trust the site's CA and serve SSH count. Without a CA it
// is nil, which tells the jump host to drop its map.
func jumpCertificates(s *Store, ca string) D {
	if ca == "" {
		return nil
	}
	reach := map[string]map[string]bool{}
	for _, t := range s.Tenants() {
		if t["status"] != "active" {
			continue
		}
		for _, m := range s.Objects("machines", integer(t["n"])) {
			if m["state"] == "deleting" || str(m["ssh_user_ca"]) != ca || str(m["ip"]) == "" || len(arr(m["service_ports"])) > 0 {
				continue
			}
			for _, p := range caPrincipals(m) {
				name := str(p)
				if !caPrincipal.MatchString(name) {
					continue
				}
				if reach[name] == nil {
					reach[name] = map[string]bool{}
				}
				reach[name][str(m["ip"])+":22"] = true
			}
		}
	}
	principals := D{}
	for name, targets := range reach {
		list := make([]string, 0, len(targets))
		for t := range targets {
			list = append(list, t)
		}
		sort.Strings(list)
		principals[name] = list
	}
	return D{"ca": ca, "principals": principals}
}

// lockJumpState takes jumpMu and reads the jump keys and certificate map, with
// the generation number that goes on both requests. The number is the clock in
// microseconds (exact in a JSON double), or one more than the last when the
// clock has not moved, so it rises across syncs and survives a restart. The
// caller unlocks after the send. A read that panics unlocks first, so a failed
// reconcile cannot block every later jump sync.
func (e *Execution) lockJumpState() (keys string, certs D, gen int64) {
	e.P.jumpMu.Lock()
	ok := false
	defer func() {
		if !ok {
			e.P.jumpMu.Unlock()
		}
	}()
	keys, certs = jumpAuthorizedKeys(e.S), jumpCertificates(e.S, e.P.Config.SSHUserCA)
	if gen = time.Now().UnixMicro(); gen <= e.P.jumpGen {
		gen = e.P.jumpGen + 1
	}
	e.P.jumpGen = gen
	ok = true
	return keys, certs, gen
}

// syncJumpNow asks for a jump sync after a key or access change and returns
// at once, so a request never waits for the jump host. One worker runs at a
// time; asks that arrive while it sends coalesce into one more pass. The pass
// reads the store and sends under jumpMu, like the reconcile path, so the last
// request sent carries the latest state. A failed send is logged by SyncJump
// and the next reconcile repairs it.
func (e *Execution) syncJumpNow() {
	if !e.jumpEnabled() {
		return
	}
	p := e.P
	p.jumpQueueMu.Lock()
	defer p.jumpQueueMu.Unlock()
	if p.jumpClosed {
		// Shutting down: the push at the next Start carries this change.
		return
	}
	p.jumpPending = true
	if p.jumpRunning {
		if p.jumpWake != nil {
			// The worker is backing off: send the new state now.
			close(p.jumpWake)
			p.jumpWake = nil
		}
		return
	}
	p.jumpRunning = true
	p.wg.Add(1)
	go p.jumpWorker()
}

// syncJumpUntilSynced is syncJumpNow for Start: the worker also resends with
// capped exponential backoff until one sync reports "synced", so a jump host
// that is briefly down does not leave a revoke waiting for Reconcile. The
// retry rides the same queue and jumpMu path, so every resend carries the
// latest state, and it ends when p.ctx is cancelled.
func (e *Execution) syncJumpUntilSynced() {
	if !e.jumpEnabled() {
		return
	}
	e.P.jumpQueueMu.Lock()
	e.P.jumpRetry = true
	e.P.jumpQueueMu.Unlock()
	e.syncJumpNow()
}

// jumpWait sleeps the retry delay, ending early when a new ask arrives or the
// platform closes.
func (p *Platform) jumpWait(d time.Duration) {
	p.jumpQueueMu.Lock()
	if p.jumpPending {
		p.jumpQueueMu.Unlock()
		return
	}
	wake := make(chan struct{})
	p.jumpWake = wake
	p.jumpQueueMu.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-wake:
	case <-p.ctx.Done():
	}
	p.jumpQueueMu.Lock()
	if p.jumpWake == wake {
		p.jumpWake = nil
	}
	p.jumpQueueMu.Unlock()
}

// jumpStatus is the jump field of a key or access result: "pending" while a
// queued sync has not confirmed or the platform is closing (the push at the
// next Start carries the change), the last failed outcome ("unavailable",
// "stale" or "keys_only") after it, and "" when jump is disabled or the host
// took the change.
func (e *Execution) jumpStatus() string {
	if !e.jumpEnabled() {
		return ""
	}
	p := e.P
	p.jumpQueueMu.Lock()
	defer p.jumpQueueMu.Unlock()
	if p.jumpPending || p.jumpRunning || p.jumpClosed {
		return "pending"
	}
	if p.jumpLast == "synced" {
		return ""
	}
	return p.jumpLast
}

// withJump adds the jump field to a handler result when there is one to show.
func (e *Execution) withJump(r D) D {
	if s := e.jumpStatus(); s != "" {
		r["jump"] = s
	}
	return r
}

func (p *Platform) jumpWorker() {
	defer p.wg.Done()
	e := p.execution(p.ctx)
	backoff := p.jumpBackoff
	if backoff <= 0 {
		backoff = time.Second
	}
	maxBackoff := p.jumpBackoffMax
	if maxBackoff <= 0 {
		maxBackoff = time.Minute
	}
	delay := backoff
	for {
		p.jumpQueueMu.Lock()
		if !p.jumpPending || p.ctx.Err() != nil {
			p.jumpRunning = false
			p.jumpPending = false
			p.jumpQueueMu.Unlock()
			return
		}
		p.jumpPending = false
		p.jumpQueueMu.Unlock()
		outcome := "unavailable"
		if f := attempt(func() {
			keys, certs, gen := e.lockJumpState()
			defer p.jumpMu.Unlock()
			outcome = e.syncJumpResending(keys, certs, gen)
		}); f != nil {
			slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		}
		p.jumpQueueMu.Lock()
		p.jumpLast = outcome
		retry := false
		if p.jumpRetry {
			if p.jumpLast == "synced" {
				p.jumpRetry = false
			} else {
				retry = true
			}
		}
		p.jumpQueueMu.Unlock()
		if retry {
			p.jumpWait(delay)
			p.jumpQueueMu.Lock()
			p.jumpPending = true
			p.jumpQueueMu.Unlock()
			if delay *= 2; delay > maxBackoff {
				delay = maxBackoff
			}
		} else {
			delay = backoff
		}
	}
}

// maxJumpResends bounds the resends after refusals, so a jump host that keeps
// reporting a higher generation cannot hold jumpMu forever.
const maxJumpResends = 3

// maxJumpGen is the first number that is not a generation: both sides keep
// generations in [0, 2^53), the range a JSON double holds exactly, and
// scripts/jump-sync.py refuses anything from here up.
const maxJumpGen = 1 << 53

// jumpResendBudget bounds the whole resend sequence in time: no resend starts
// after it, so a slow jump host cannot hold jumpMu for maxJumpResends rounds
// of two full timeouts. A var so a test can shrink it.
var jumpResendBudget = 90 * time.Second

// syncJumpResending is SyncJump plus resends: a refusal that moved jumpGen
// past the generation sent means the jump host holds a newer floor, so the
// same state goes again above it. It stops when both requests pass, when no
// new floor was learned, after maxJumpResends, when jumpResendBudget has run
// out, or when the next generation would leave [0, 2^53). The caller holds
// jumpMu.
func (e *Execution) syncJumpResending(keys string, certs D, gen int64) string {
	start := time.Now()
	outcome := e.SyncJump(keys, certs, gen)
	for i := 0; i < maxJumpResends && (outcome == "stale" || outcome == "keys_only") && e.P.jumpGen > gen &&
		e.P.jumpGen < maxJumpGen-1 && time.Since(start) < jumpResendBudget; i++ {
		e.P.jumpGen++
		gen = e.P.jumpGen
		outcome = e.SyncJump(keys, certs, gen)
	}
	return outcome
}

// SyncJump sends the jump host its keys, then the certificate map in a
// separate request, so a jump host that predates certificates still takes
// keys. The map goes every time, nil included: the jump host drops it when
// the site has no CA, and stops using it when no control plane has sent one
// for a while (jump-cert.py). Both requests carry gen, so jump-sync.py can
// refuse a write older than the one it holds; a refused keys write reports
// "stale" and a refused certs write "keys_only". A jump host that cannot be reached costs
// members only that path, so it does not fail the reconcile.
func (e *Execution) SyncJump(keys string, certs D, gen int64) string {
	if gen < 0 || gen >= maxJumpGen {
		// The jump host refuses it, and a floor that high could not be passed.
		slog.Error("jump_sync_gen_range", "event", "jump_sync_gen_range")
		return "unavailable"
	}
	var res any
	if f := attempt(func() { res = e.Call(D{"op": "sync", "authorized": keys, "gen": gen}, jumpTarget) }); f != nil {
		slog.Error("jump_sync_failed", "event", "jump_sync_failed")
		return "unavailable"
	}
	// jumpMu orders this process's writes, so a refusal means the jump host
	// holds a generation ahead of ours (a clock stepped back, or a lost
	// state): the old keys stay, which is an error. The worker resends
	// above the held one.
	if _, ok := res.(map[string]any); !ok {
		// No acknowledgment object: the host did not confirm the keys.
		slog.Error("jump_sync_unusable", "event", "jump_sync_unusable")
		return "unavailable"
	}
	if obj(res)["stale"] == true {
		e.raiseJumpGen(res)
		slog.Error("jump_sync_stale", "event", "jump_sync_stale", "gen", gen)
		return "stale"
	}
	if f := attempt(func() { res = e.Call(D{"op": "certs", "certs": certs, "gen": gen}, jumpTarget) }); f != nil {
		slog.Error("jump_certs_failed", "event", "jump_certs_failed")
		return "keys_only"
	}
	if _, ok := res.(map[string]any); !ok {
		slog.Error("jump_certs_unusable", "event", "jump_certs_unusable")
		return "keys_only"
	}
	if obj(res)["stale"] == true {
		e.raiseJumpGen(res)
		slog.Error("jump_certs_stale", "event", "jump_certs_stale", "gen", gen)
		return "keys_only"
	}
	return "synced"
}

// raiseJumpGen lifts jumpGen to the generation a refusal says the jump host
// holds, so the next number sent is above it. The caller holds jumpMu.
func (e *Execution) raiseJumpGen(res any) {
	// held comes from the jump host: only an exact integer in [0, 2^53) is
	// a generation, anything else is ignored.
	held, ok := obj(res)["held"].(float64)
	if !ok || held < 0 || held >= maxJumpGen || held != math.Trunc(held) {
		return
	}
	if int64(held) > e.P.jumpGen {
		e.P.jumpGen = int64(held)
	}
}
