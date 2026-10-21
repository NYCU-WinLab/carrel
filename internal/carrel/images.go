package carrel

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// Tenant images and ISOs (PLAN 7.8). The fetch container downloads a file;
// the first exit node checks it and moves it onto the site's shared storage
// as carrel-tNNN-<name>-<12 hex of its SHA-256>.<iso|qcow2|raw>. Its size
// counts against images_gb, together with app releases (7.9).

const maxImageBytes = 20 << 30

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

type imageRecord struct {
	CreatedAt   int64  `json:"created_at"`
	ID          string `json:"id"`
	Job         string `json:"job"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	OperationID string `json:"operation_id,omitempty"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	State       string `json:"state"`
	TenantN     int    `json:"tenant_n"`
	URL         string `json:"url"`
	Volume      string `json:"volume,omitempty"`
}

func (r imageRecord) public() D {
	return D{"name": r.Name, "kind": r.Kind, "sha256": r.SHA256, "size_bytes": r.Size, "state": r.State, "volume": orNil(r.Volume), "created_at": r.CreatedAt}
}

func (r imageRecord) file() string {
	ext := r.Kind
	return fmt.Sprintf("carrel-t%03d-%s-%s.%s", r.TenantN, r.Name, r.SHA256[:12], ext)
}

func (e *Execution) images(n int) []imageRecord { return rowsOf[imageRecord](e.S, "images", n) }

// imageBytes is what a tenant's images hold, a download in flight counted
// at the space it reserved.
func (e *Execution) imageBytes(n int) float64 {
	total := 0.0
	for _, r := range e.images(n) {
		total += float64(r.Size)
	}
	return total
}

func (e *Execution) imageUsage(t D) D {
	n := integer(t["n"])
	used := e.storedBytes(n) + e.imageBytes(n)
	return D{"used_gib": used / GiB, "limit_gib": obj(t["quota"])["images_gb"]}
}

func (e *Execution) ImageAction(tool string, a, t D) D {
	n := integer(t["n"])
	switch tool {
	case "image_list":
		out := []D{}
		for _, r := range e.images(n) {
			out = append(out, r.public())
		}
		return D{"images": out, "images_gb": e.imageUsage(t)}
	case "image_delete":
		r, ok := e.imageNamed(n, str(a["name"]))
		if !ok {
			fail("not_found", "Image not found in this tenant")
		}
		if a["confirm"] != r.Name {
			fail("invalid", "confirm must equal the image name")
		}
		if r.State != "ready" {
			fail("conflict", "The image is still being imported", D{"recovery": "resolve_prerequisite"})
		}
		if boolean(a["dry_run"]) {
			return D{"image": r.public(), "dry_run": true, "images_gb": e.imageUsage(t)}
		}
		e.Call(D{"op": "image_delete", "tenant_n": n, "volume": r.file(), "kind": imageStorageKind(r.Kind)}, e.P.Nodes()[0].Target)
		e.S.Remove("images", r.ID)
		r.State = "deleted"
		return D{"image": r.public(), "dry_run": false, "images_gb": e.imageUsage(t)}
	}
	fail("invalid", "Unknown image tool")
	return nil
}

func imageStorageKind(kind string) string {
	if kind == "iso" {
		return "iso"
	}
	return "import"
}

func (e *Execution) imageNamed(n int, name string) (imageRecord, bool) {
	for _, r := range e.images(n) {
		if r.Name == name {
			return r, true
		}
	}
	return imageRecord{}, false
}

// PlanImport checks and reserves an import under the writer lock.
func (e *Execution) PlanImport(tool string, a, t D) D {
	n := integer(t["n"])
	if plan := obj(obj(e.Op)["import"]); plan["id"] != nil {
		if r, ok := rowOf[imageRecord](e.S, "images", str(plan["id"])); ok {
			return D{"image": r.public()}
		}
	}
	if !boolean(e.P.Config["fetch"]) {
		fail("invalid", "This site has no image fetcher", D{"recovery": "revise_request"})
	}
	kind := "iso"
	name, url, sum := str(a["name"]), str(a["url"]), str(a["sha256"])
	if !labelPattern.MatchString(name) {
		fail("invalid", "Name must be a lowercase label")
	}
	if !sha256Hex.MatchString(sum) {
		fail("invalid", "sha256 must be 64 lowercase hex digits")
	}
	if _, taken := e.imageNamed(n, name); taken {
		fail("conflict", "An image with this name exists", D{"recovery": "revise_request"})
	}
	// One import per tenant, 3 per site: the rest wait for a slot.
	if e.Op != nil {
		mine, all := 0, 0
		for _, other := range e.S.ActiveOperations() {
			if other["id"] == e.Op["id"] || other["import"] == nil {
				continue
			}
			all++
			if integer(other["tenant_n"]) == n {
				mine++
			}
		}
		if mine >= 1 || all >= 3 {
			panic(Waiting{"waiting_for_import_slot", now() + 30})
		}
	}
	limit := num(obj(t["quota"])["images_gb"]) * GiB
	room := limit - e.storedBytes(n) - e.imageBytes(n)
	reserve := int64(min(float64(maxImageBytes), room))
	if reserve < 1<<20 {
		fail("quota_exceeded", "images_gb is full", D{"dimension": "images_gb", "images_gb": e.imageUsage(t), "recovery": "remove_unused"})
	}
	r := imageRecord{ID: randomID()[:16], TenantN: n, Name: name, Kind: kind, URL: url, SHA256: sum, Size: reserve, State: "fetching", Job: randomID(), CreatedAt: time.Now().Unix()}
	if boolean(a["dry_run"]) {
		return D{"image": merge(r.public(), D{"state": "planned"}), "dry_run": true, "images_gb": e.imageUsage(t)}
	}
	refused := []any{}
	if ip, err := netip.ParseAddr(str(e.P.Config["public_address"])); err == nil {
		refused = append(refused, ip.String()+"/32")
	}
	e.Put("images", r.ID, n, r)
	if f := attempt(func() {
		e.Call(D{"op": "fetch_start", "job": r.Job, "url": url, "sha256": sum, "max_bytes": reserve, "format": kind, "refused": refused}, e.P.Nodes()[0].Target)
	}); f != nil {
		// Nothing started, or nothing anyone tracks: the reservation goes,
		// and so does whatever the container may have begun.
		_ = attempt(func() { e.Call(D{"op": "fetch_clean", "job": r.Job}, e.P.Nodes()[0].Target) })
		e.S.Remove("images", r.ID)
		panic(f)
	}
	if e.Op != nil {
		e.Op["import"] = D{"id": r.ID}
		e.P.Operations.Save(e.Op)
	}
	return D{"image": r.public()}
}

// PerformImport waits for the download outside the writer lock, then stores
// the file. A failure removes the record and the staged file.
func (e *Execution) PerformImport() {
	if e.Op["tool"] != "iso_import" || e.Op["import"] == nil {
		return
	}
	id := str(obj(e.Op["import"])["id"])
	r, ok := rowOf[imageRecord](e.S, "images", id)
	if !ok || r.State == "ready" {
		return
	}
	target := e.P.Nodes()[0].Target
	abandon := func(code, message string) {
		// A shutdown is not a failure: the job resumes after the restart.
		if err := e.Ctx.Err(); err != nil {
			panic(err)
		}
		_ = attempt(func() { e.Call(D{"op": "fetch_clean", "job": r.Job}, target) })
		e.P.writer.Lock()
		e.S.Remove("images", id)
		e.P.writer.Unlock()
		fail(code, message, D{"recovery": "revise_request"})
	}
	func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["phase"] = "downloading"
		e.P.Operations.Save(e.Op)
	}()
	misses := 0
	for {
		var status D
		if f := attempt(func() { status = obj(e.Call(D{"op": "fetch_status", "job": r.Job}, target)) }); f != nil {
			// A node that does not answer once is not a failed download.
			if misses++; misses >= 6 || e.Ctx.Err() != nil {
				panic(f)
			}
			status = D{"state": "running"}
		} else {
			misses = 0
		}
		if status["state"] == "done" {
			break
		}
		if status["state"] == "failed" {
			res := obj(status["result"])
			abandon(textAt(res, "code", "fetch_failed"), textAt(res, "error", "The download failed"))
		}
		select {
		case <-e.Ctx.Done():
			panic(e.Ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
	stored := D{}
	if f := attempt(func() {
		stored = obj(e.Call(D{"op": "fetch_store", "job": r.Job, "volume": r.file(), "kind": imageStorageKind(r.Kind), "sha256": r.SHA256, "tenant_n": r.TenantN, "max_bytes": r.Size}, target))
	}); f != nil {
		abandon("backend_unavailable", "The image could not be stored")
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	if cur, ok := rowOf[imageRecord](e.S, "images", id); ok {
		cur.State, cur.Volume = "ready", str(stored["volume"])
		if s := int64(num(stored["size"])); s > 0 {
			cur.Size = s
		}
		e.Put("images", cur.ID, cur.TenantN, cur)
	}
}

// FinishImport reports the stored image.
func (e *Execution) FinishImport() D {
	r, ok := rowOf[imageRecord](e.S, "images", str(obj(e.Op["import"])["id"]))
	if !ok || r.State != "ready" {
		fail("backend_unavailable", "The image was not stored", D{"recovery": "retry_infrastructure"})
	}
	return D{"image": r.public()}
}
