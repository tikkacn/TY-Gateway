package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"tygateway/internal/model"
)

// Opt-in, isolated database ONLY. Never point this test at the TY production DB.
// The caller creates/removes the database and injects credentials in memory.
func TestDeactivateDeviceSQLAtomicity(t *testing.T) {
	dsn := os.Getenv("TY_DEACTIVATION_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated MySQL fixture not provided")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil || !strings.HasPrefix(cfg.DBName, "ty_deactivation_test_") {
		t.Fatal("refusing non-isolated test database")
	}
	s, err := OpenMySQL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, name := range []string{"001_initial.sql", "002_customer_identity.sql", "003_customer_portal.sql", "004_customer_session_version.sql", "005_device_rescue_ssh_port.sql", "006_device_enrollments.sql", "007_mac_first_claim.sql", "008_device_deactivation.sql", "008_device_deactivation.sql"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				lines = append(lines, line)
			}
		}
		for _, statement := range strings.Split(strings.Join(lines, "\n"), ";") {
			if strings.TrimSpace(statement) != "" {
				if _, err := s.db.ExecContext(ctx, statement); err != nil {
					t.Fatalf("fixture %s: %v", name, err)
				}
			}
		}
	}
	sub, err := s.CreateSubscription(ctx, "source", "test", []byte("encrypted-test"))
	if err != nil {
		t.Fatal(err)
	}
	const mac = "02:00:00:00:93:01"
	const oldSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := s.PrepareMACDeviceEnrollment(ctx, mac, "fixture", "gfw_precise", sub.ID); err != nil {
		t.Fatal(err)
	}
	d, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: oldSecret})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDevice(ctx, d.ID, model.DeviceEnabled, "current fixture", "managed_meta"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AllocateRescueSSHPort(ctx, d.ID, 22000, 22001); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain", MatchValue: "example.test", Action: "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCustomerNodePreference(ctx, d.ID, "ai", "@direct"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "report_status"}); err != nil {
		t.Fatal(err)
	}
	d, _ = s.GetDevice(ctx, d.ID)
	// Fail the audit write after inserting the revocation hash. Neither may
	// remain, and the device/enrollment must still be untouched.
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_test_audit BEFORE INSERT ON identity_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='test audit failure'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac); err == nil {
		t.Fatal("audit failure ignored")
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM revoked_device_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial revocation committed")
	}
	if _, err := s.GetDeviceAuth(ctx, d.ID); err != nil {
		t.Fatal("failed reset removed device")
	}
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER reject_test_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion-1, mac); !errors.Is(err, ErrConflict) {
		t.Fatal("stale version accepted")
	}
	record, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac)
	if err != nil || record.ClaimedAt != nil || record.DeviceID != "" || record.Note != "current fixture" || record.Profile != "managed_meta" || record.SubscriptionID != sub.ID {
		t.Fatalf("reset result: %#v %v", record, err)
	}
	for _, table := range []string{"devices", "rules", "customer_node_preferences", "commands"} {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("cascade %s: %d %v", table, count, err)
		}
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_events WHERE event_type='device_deactivated'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("audit event missing")
	}
	if _, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: oldSecret}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("revoked SQL claim: %v", err)
	}
	if _, err := s.PrepareMACDeviceEnrollment(ctx, "02:00:00:00:93:02", "", "", sub.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("preserved subscription was not reserved")
	}
	fresh, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: strings.Repeat("b", 64)})
	if err != nil || fresh.ID == d.ID || fresh.DeviceNumber <= d.DeviceNumber || fresh.RescueSSHPort != 0 {
		t.Fatalf("fresh SQL claim: %#v %v", fresh, err)
	}
	if _, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac); !errors.Is(err, ErrNotFound) {
		t.Fatal("old drawer accepted")
	}
	if cipher, err := s.GetSubscriptionCiphertext(ctx, sub.ID); err != nil || string(cipher) != "encrypted-test" {
		t.Fatal("shared subscription changed")
	}
}
