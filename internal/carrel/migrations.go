package carrel

import (
	"context"
	"fmt"
)

// Raise only untouched legacy count limits. Explicit admin limits and temporary
// grants retain their original meaning, including limits equal to the old default.
func (s *Store) migrateSmallDefaults() (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("migrate small defaults: %v", value)
		}
	}()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	m := &Store{s.DB, tx}
	const id = "0.9.0-small-defaults"
	if len(m.Rows("SELECT id FROM migrations WHERE id=?", id)) != 0 {
		return nil
	}
	for _, tenant := range m.Tenants() {
		custom := map[string]bool{}
		for _, row := range m.Rows("SELECT args FROM audit WHERE tenant=? AND tool='quota_set' AND outcome='ok'", tenant["n"]) {
			args := decode(str(row["args"]))
			if !boolean(args["dry_run"]) {
				custom[str(args["dimension"])] = true
			}
		}
		for _, request := range m.Objects("requests", integer(tenant["n"])) {
			if request["kind"] == "quota" && (request["previous_limit"] != nil || request["status"] == "approved") {
				custom[str(request["dimension"])] = true
			}
		}
		quota, changed := obj(tenant["quota"]), D{}
		for _, dim := range []string{"machines", "ips"} {
			if num(quota[dim]) == 4 && !custom[dim] {
				quota[dim], changed[dim] = 8, D{"before": 4, "after": 8}
			}
		}
		if len(changed) > 0 {
			m.Exec("UPDATE tenants SET quota=? WHERE n=?", string(encoded(quota)), tenant["n"])
			m.Log("system", tenant["n"], "quota_defaults_migrate", D{"migration": id, "changes": changed}, "ok")
		}
	}
	m.Exec("INSERT INTO migrations(id,applied_at) VALUES(?,?)", id, now())
	return tx.Commit()
}
