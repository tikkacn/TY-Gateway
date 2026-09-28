package main

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"testing"

	"tygateway/internal/httpapi"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestAgentNodeInventoryRequestMatchesCloudAPI(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:80:01"})
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := st.CreateSubscription(ctx, "test", "v2board", []byte("encrypted-provider-url"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BindSubscription(ctx, device.ID, subscription.ID); err != nil {
		t.Fatal(err)
	}

	cloud := httptest.NewServer(httpapi.NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef")))
	defer cloud.Close()
	agent := &agent{
		server: cloud.URL,
		client: cloud.Client(),
		state:  credentialState{DeviceID: device.ID, DeviceSecret: secret},
		logger: log.New(io.Discard, "", 0),
	}

	// dae-native identities may acquire Region/Group for display elsewhere;
	// the Cloud API deliberately accepts only the validated ID/name pair.
	withDisplayMetadata := []model.CustomerNode{{ID: "0123456789abcdef", Name: "新加坡节点", Region: "SG", Group: "旧分组"}}
	if err := agent.reportValidatedNodes(ctx, subscription.ID, nodeIdentities(withDisplayMetadata)); err != nil {
		t.Fatalf("Agent's sanitized inventory request was rejected by Cloud: %v", err)
	}
	committed, err := st.GetSubscriptionNodes(ctx, subscription.ID)
	if err != nil || len(committed) != 1 || committed[0].ID != withDisplayMetadata[0].ID || committed[0].Name != withDisplayMetadata[0].Name || committed[0].Server != "" {
		t.Fatalf("Cloud did not persist the safe validated identity: %#v, %v", committed, err)
	}

	if err := agent.reportValidatedNodes(ctx, subscription.ID, withDisplayMetadata); err == nil {
		t.Fatal("Agent accepted Cloud's rejection of inventory containing display-only metadata")
	}
}
