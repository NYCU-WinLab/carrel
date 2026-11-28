package svc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// legacyManifest is the name a service's manifest had while services were
// called functions (#908).
const legacyManifest = "function.json"

// AdoptLegacyManifests renames the manifests a host kept under the old name,
// <root>/<name>/function.json and <root>/<name>/v/<version>/function.json,
// to service.json, so the first pass after an upgrade finds the live and
// built versions instead of building them again. It follows no link and
// leaves a directory alone when service.json is already there. It returns
// how many it renamed.
func AdoptLegacyManifests(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	renamed := 0
	adopt := func(dir string) error {
		old := filepath.Join(dir, legacyManifest)
		info, err := os.Lstat(old)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if _, err := os.Lstat(filepath.Join(dir, "service.json")); err == nil {
			return nil
		}
		if err := os.Rename(old, filepath.Join(dir, "service.json")); err != nil {
			return err
		}
		renamed++
		return nil
	}
	realDir := func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.IsDir()
	}
	for _, e := range entries {
		name := e.Name()
		dir := filepath.Join(root, name)
		if strings.HasPrefix(name, ".") || !realDir(dir) {
			continue
		}
		if err := adopt(dir); err != nil {
			return renamed, err
		}
		versions, err := os.ReadDir(filepath.Join(dir, "v"))
		if err != nil || !realDir(filepath.Join(dir, "v")) {
			continue
		}
		for _, v := range versions {
			vdir := filepath.Join(dir, "v", v.Name())
			if !realDir(vdir) {
				continue
			}
			if err := adopt(vdir); err != nil {
				return renamed, err
			}
		}
	}
	return renamed, nil
}
