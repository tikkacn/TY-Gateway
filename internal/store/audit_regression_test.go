package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"tygateway/internal/identity"
	"tygateway/internal/model"
)

func TestAuditMemoryRegression(t *testing.T) { auditStore(t, NewMemoryStore(), nil) }
func TestAuditMySQLRegression(t *testing.T) {
	dsn := os.Getenv("TY_AUDIT_DB_DSN")
	if dsn == "" {
		t.Skip("explicit audit database connection not supplied")
	}
	st, err := OpenMySQL(dsn)
	if err != nil {
		t.Fatal("database open failed")
	}
	defer st.Close()
	auditStore(t, st, st)
}
func auditStore(t *testing.T, st Store, sqlStore *SQLStore) {
	ctx := context.Background()
	mac := "02" + identity.NewID()[:10]
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: mac, AgentVersion: "audit-regression"})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := st.CreateSubscription(ctx, "audit-regression", "fixture", []byte("not-a-subscription"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlStore != nil {
			if _, err := sqlStore.db.ExecContext(ctx, `DELETE FROM identity_events WHERE device_id IN (?,?)`, d.ID, sub.ID); err != nil {
				t.Error("event cleanup failed")
			}
			if _, err := sqlStore.db.ExecContext(ctx, `DELETE FROM devices WHERE id=? AND agent_version='audit-regression'`, d.ID); err != nil {
				t.Error("device cleanup failed")
			}
			if _, err := sqlStore.db.ExecContext(ctx, `DELETE FROM subscriptions WHERE id=? AND name='audit-regression'`, sub.ID); err != nil {
				t.Error("subscription cleanup failed")
			}
		}
	}()
	d, err = st.UpdateIdentity(ctx, d.ID, "audit", "audit-"+d.ID+"@example.invalid", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	d, _, err = st.RotateCustomerAccess(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.GetCustomerAuthBySerial(ctx, d.Serial)
	if err != nil || a.Version != d.CustomerSessionVersion {
		t.Fatal("credential version mismatch")
	}
	if err = st.RevokeCustomerSessions(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	a2, _ := st.GetCustomerAuthBySerial(ctx, d.Serial)
	if a2.Version != a.Version+1 {
		t.Fatal("revoke version mismatch")
	}
	for i := 0; i < 5; i++ {
		if _, err = st.Heartbeat(ctx, d.ID, model.DeviceReport{}); err != nil {
			t.Fatalf("repeated heartbeat %d: %v", i, err)
		}
	}
	if err = st.ReplaceSubscriptionNodes(ctx, sub.ID, []model.Node{{ID: "node-a", Name: "fixture", Protocol: "test", Server: "example.invalid", Group: "HK"}}); err != nil {
		t.Fatal(err)
	}
	if err = st.SetCustomerNodePreference(ctx, d.ID, "GFW", "node-a"); err != nil {
		t.Fatal(err)
	}
	if err = st.SetCustomerNodePreference(ctx, d.ID, "GFW", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign node accepted")
	}
	var successes, conflicts atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := st.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain", MatchValue: "audit.example", Action: "NODE:node-a", Priority: 100})
			if e == nil {
				successes.Add(1)
			} else if errors.Is(e, ErrConflict) {
				conflicts.Add(1)
			} else {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || conflicts.Load() != 19 {
		t.Fatal("concurrent duplicate protection failed")
	}
	rs, err := st.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rs) != 1 {
		t.Fatal("customer rules mismatch")
	}
	before, _ := st.GetDevice(ctx, d.ID)
	rs[0].Action = "GROUP:HK"
	if _, err = st.SaveCustomerRule(ctx, rs[0]); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetDevice(ctx, d.ID)
	if after.ConfigVersion != before.ConfigVersion+1 {
		t.Fatal("edit version mismatch")
	}
	adminRule, err := st.CreateRule(ctx, model.Rule{DeviceID: d.ID, Source: "admin", SourceType: "user", MatchType: "domain", MatchValue: "protected.example", Action: "DIRECT", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.DeleteRuleForDevice(ctx, adminRule.ID, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("admin rule deletion allowed")
	}
	if err = st.DeleteRuleForDevice(ctx, rs[0].ID, d.ID); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	before, _ = st.GetDevice(ctx, d.ID)
	if _, err = st.SetCustomerOverride(ctx, d.ID, "PROXY", &past); err != nil {
		t.Fatal(err)
	}
	after, _ = st.GetDevice(ctx, d.ID)
	if after.CustomerOverrideAction != "" || after.ConfigVersion != before.ConfigVersion+2 {
		t.Fatal("expiry not persisted/versioned")
	}
	again, _ := st.GetDevice(ctx, d.ID)
	if again.ConfigVersion != after.ConfigVersion {
		t.Fatal("expiry repeated version bump")
	}
	if err = st.ReplaceSubscriptionNodes(ctx, sub.ID, nil); err != nil {
		t.Fatal(err)
	}
	prefs, err := st.ListCustomerNodePreferences(ctx, d.ID)
	if err != nil || len(prefs) != 0 {
		t.Fatal("stale preferences retained")
	}
	c, err := st.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "report_status"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := st.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "report_status"})
	if err != nil || c2.ID != c.ID {
		t.Fatal("command deduplication failed")
	}
	if err = st.RecordEvent(ctx, d.ID, "audit_test"); err != nil {
		t.Fatal(err)
	}
	d, err = st.UpdateIdentity(ctx, d.ID, "new owner", "next-"+d.ID+"@example.invalid", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, err = st.GetCustomerAuthBySerial(ctx, d.Serial)
	if err != nil || a.CustomerAccessHash != "" {
		t.Fatal("owner change retained access credential")
	}
}
