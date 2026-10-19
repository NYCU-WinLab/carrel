package carrel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// nodeFiles are the files under /etc/carrel on each node that a backup keeps:
// none holds a secret, and none can be rebuilt from the database.
var nodeFiles = []string{"node.json", "templates.json", "site.json"}

func (p *Platform) Backup(ctx context.Context, configDir string) (result D, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = errors.New("control backup failed")
		}
	}()
	folder, e := os.MkdirTemp(filepath.Dir(str(p.Config["database"])), "backup-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(folder)
	database := filepath.Join(folder, "carrel.db")
	p.Store.Exec("VACUUM INTO ?", database)
	check, e := OpenStore(database)
	if e != nil {
		return nil, e
	}
	integrity := check.Rows("PRAGMA integrity_check")
	check.DB.Close()
	if len(integrity) != 1 || integrity[0]["integrity_check"] != "ok" {
		return nil, errors.New("backup database integrity failure")
	}
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(gz)
	add := func(source, name string) error {
		return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				link, err = os.Readlink(path)
				if err != nil {
					return err
				}
			}
			header, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(name)
			if rel != "." {
				header.Name += "/" + filepath.ToSlash(rel)
			}
			if err = archive.WriteHeader(header); err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				_, err = io.Copy(archive, f)
				f.Close()
				return err
			}
			return nil
		})
	}
	if e = add(database, "carrel.db"); e != nil {
		return nil, e
	}
	for _, name := range []string{"config.json", "node_key", "node_key.pub", "ssh_config", "known_hosts"} {
		if e = add(filepath.Join(configDir, name), "etc/carrel/"+name); e != nil {
			return nil, e
		}
	}
	certificates := p.execution(ctx).CertificateDir()
	if _, e = os.Stat(certificates); e == nil {
		if e = add(certificates, "certificates"); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	// Node files a reconcile cannot derive (PLAN 15.15 gap 8). A node that
	// does not answer is reported; the backup of everything else still lands.
	missing := []any{}
	for _, n := range p.Nodes() {
		reply, err := p.Backend.Call(ctx, D{"op": "node_files"}, n.Target)
		name := str(obj(reply)["node"])
		if err != nil || !nodeName.MatchString(name) {
			missing = append(missing, n.Target)
			continue
		}
		for file, content := range obj(obj(reply)["files"]) {
			if !contains(nodeFiles, file) {
				continue
			}
			data := []byte(str(content))
			header := &tar.Header{Name: "nodes/" + name + "/" + file, Mode: 0600, Size: int64(len(data)), ModTime: time.Now(), Typeflag: tar.TypeReg}
			if e = archive.WriteHeader(header); e != nil {
				return nil, e
			}
			if _, e = archive.Write(data); e != nil {
				return nil, e
			}
		}
	}
	if e = archive.Close(); e != nil {
		return nil, e
	}
	if e = gz.Close(); e != nil {
		return nil, e
	}
	if buffer.Len() > 10_000_000 {
		return nil, errors.New("backup exceeds bounded transfer size")
	}
	response, e := p.Backend.Call(ctx, D{"op": "backup", "archive": base64.StdEncoding.EncodeToString(buffer.Bytes())}, "carrel-edge")
	if e != nil {
		return nil, e
	}
	if len(missing) > 0 {
		return merge(obj(response), D{"missing_nodes": missing}), nil
	}
	return obj(response), nil
}
