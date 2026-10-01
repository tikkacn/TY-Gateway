// Additive, resumable migration. Run with TY service stopped after a database backup.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"strings"
	"time"
	"tygateway/internal/subscription"
)

func main() {
	if err := migrate(); err != nil {
		fmt.Fprintln(os.Stderr, "identity migration failed; inspect schema and duplicate bindings without printing secrets")
		os.Exit(1)
	}
	fmt.Println("identity migration verified")
}
func migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := sql.Open("mysql", os.Getenv("TY_DB_DSN"))
	if err != nil {
		return err
	}
	defer db.Close()
	key, err := subscription.KeyFromString(os.Getenv("TY_SUBSCRIPTION_KEY"))
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, `SELECT id,url_ciphertext FROM subscriptions`)
	if err != nil {
		return err
	}
	digests := map[string]string{}
	seen := map[string]bool{}
	for rows.Next() {
		var id string
		var ciphertext []byte
		if err = rows.Scan(&id, &ciphertext); err != nil {
			rows.Close()
			return err
		}
		plain, e := subscription.DecryptURL(ciphertext, key)
		if e != nil {
			rows.Close()
			return e
		}
		h := hmac.New(sha256.New, key)
		h.Write([]byte("subscription-lookup-v1\x00" + strings.TrimSpace(plain)))
		digest := hex.EncodeToString(h.Sum(nil))
		if seen[digest] {
			rows.Close()
			return fmt.Errorf("duplicate subscriptions")
		}
		seen[digest] = true
		digests[id] = digest
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var duplicates int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT subscription_id FROM devices WHERE subscription_id IS NOT NULL GROUP BY subscription_id HAVING COUNT(*)>1) d`).Scan(&duplicates); err != nil {
		return err
	}
	if duplicates > 0 {
		return fmt.Errorf("duplicate bindings")
	}
	for _, c := range []struct{ table, name, ddl string }{
		{"devices", "name", "ADD COLUMN name VARCHAR(128) NOT NULL DEFAULT ''"},
		{"devices", "email", "ADD COLUMN email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_general_ci NULL"},
		{"devices", "customer_access_hash", "ADD COLUMN customer_access_hash CHAR(64) NULL"},
		{"devices", "customer_session_version", "ADD COLUMN customer_session_version BIGINT NOT NULL DEFAULT 0"},
		{"devices", "customer_override_action", "ADD COLUMN customer_override_action VARCHAR(16) NOT NULL DEFAULT ''"},
		{"devices", "customer_override_until", "ADD COLUMN customer_override_until DATETIME(6) NULL"},
		{"subscriptions", "url_lookup", "ADD COLUMN url_lookup CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL"},
	} {
		var n int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`, c.table, c.name).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err = db.ExecContext(ctx, "ALTER TABLE "+c.table+" "+c.ddl); err != nil {
				return err
			}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, digest := range digests {
		if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET url_lookup=? WHERE id=?`, digest, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, idx := range []struct{ table, name, column string }{{"devices", "uq_device_email", "email"}, {"devices", "uq_device_subscription", "subscription_id"}, {"subscriptions", "uq_subscription_url", "url_lookup"}} {
		var n int
		if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=?`, idx.table, idx.name).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err = db.ExecContext(ctx, "ALTER TABLE "+idx.table+" ADD UNIQUE KEY "+idx.name+" ("+idx.column+")"); err != nil {
				return err
			}
		}
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_events (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,device_id CHAR(32) NOT NULL,event_type VARCHAR(32) NOT NULL,created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6))`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS customer_node_preferences (device_id CHAR(32) NOT NULL,category VARCHAR(64) NOT NULL,node_id VARCHAR(64) NOT NULL,updated_at DATETIME(6) NOT NULL,PRIMARY KEY (device_id,category),CONSTRAINT fk_customer_pref_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE)`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS revoked_device_credentials (secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,device_id CHAR(32) NOT NULL,serial VARCHAR(32) NOT NULL,revoked_at DATETIME(6) NOT NULL,KEY idx_revoked_device (device_id))`)
	return err
}
