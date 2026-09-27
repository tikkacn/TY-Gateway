package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"tygateway/internal/auth"
	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/selection"
)

var ErrNotFound = errors.New("not found")
var ErrAlreadyRegistered = errors.New("device already registered")
var ErrConflict = errors.New("identity already bound")
var ErrLimit = errors.New("limit reached")
var ErrInvalidActivation = errors.New("invalid or expired device activation")

type Store interface {
	RegisterDevice(context.Context, model.RegisterDeviceInput) (model.Device, string, error)
	PrepareDeviceEnrollment(context.Context, string, string, string, string) (model.DeviceEnrollment, string, error)
	PrepareMACDeviceEnrollment(context.Context, string, string, string, string) (model.DeviceEnrollment, error)
	ListDeviceEnrollments(context.Context) ([]model.DeviceEnrollment, error)
	RevokeDeviceEnrollment(context.Context, string) error
	RegisterApprovedDevice(context.Context, model.RegisterDeviceInput) (model.Device, string, error)
	RegisterMACClaim(context.Context, model.RegisterDeviceInput) (model.Device, string, error)
	GetDevice(context.Context, string) (model.Device, error)
	GetDeviceAuth(context.Context, string) (model.DeviceAuth, error)
	GetCustomerAuthBySerial(context.Context, string) (model.CustomerAuth, error)
	RotateCustomerAccess(context.Context, string) (model.Device, string, error)
	RevokeCustomerSessions(context.Context, string) error
	RecordEvent(context.Context, string, string) error
	ListDevices(context.Context, time.Duration) ([]model.Device, error)
	SetRescueSSHPort(context.Context, string, int) error
	AllocateRescueSSHPort(context.Context, string, int, int) (int, error)
	UpdateDevice(context.Context, string, model.DeviceState, string, string) (model.Device, error)
	Heartbeat(context.Context, string, model.DeviceReport) (model.Device, error)
	ListRules(context.Context, string) ([]model.Rule, error)
	CreateRule(context.Context, model.Rule) (model.Rule, error)
	DeleteRule(context.Context, string) error
	ReplaceProviderRules(context.Context, string, []model.Rule) error
	CreateSubscription(context.Context, string, string, []byte, ...string) (model.SubscriptionView, error)
	DeleteSubscription(context.Context, string) (int, error)
	UpdateIdentity(context.Context, string, string, string, string) (model.Device, error)
	SetCustomerOverride(context.Context, string, string, *time.Time) (model.Device, error)
	ListCustomerRules(context.Context, string) ([]model.Rule, error)
	SaveCustomerRule(context.Context, model.Rule) (model.Rule, error)
	DeleteRuleForDevice(context.Context, string, string) error
	SetCustomerNodePreference(context.Context, string, string, string) error
	ListCustomerNodePreferences(context.Context, string) (map[string]string, error)
	ReplaceCustomerSettings(context.Context, string, int64, []model.CustomerSettingRule, map[string]string) (int64, error)
	ListSubscriptions(context.Context) ([]model.SubscriptionView, error)
	FindSubscriptionByLookup(context.Context, string) (model.SubscriptionView, error)
	GetSubscriptionCiphertext(context.Context, string) ([]byte, error)
	UpdateSubscriptionStatus(context.Context, string, string, int) error
	GetSubscriptionNodes(context.Context, string) ([]model.Node, error)
	ReplaceSubscriptionNodes(context.Context, string, []model.Node) error
	CommitValidatedNodes(context.Context, string, string, []model.CustomerNode) error
	BindSubscription(context.Context, string, string) error
	EnqueueCommand(context.Context, model.Command) (model.Command, error)
	ListDeviceCommands(context.Context, string) ([]model.Command, error)
	PollCommands(context.Context, string) ([]model.Command, error)
	AckCommand(context.Context, string, string, string) error
}

type MemoryStore struct {
	mu                sync.RWMutex
	devices           map[string]model.Device
	deviceSecrets     map[string]string
	deviceEnrollments map[string]memoryEnrollment
	customerSecrets   map[string]string
	rules             map[string]model.Rule
	subscriptions     map[string]memorySubscription
	commands          map[string]model.Command
	subscriptionNodes map[string][]model.Node
	customerNodePrefs map[string]map[string]string
	nextNumber        int64
}

type memorySubscription struct {
	model.SubscriptionView
	ciphertext []byte
	lookup     string
}

type memoryEnrollment struct {
	model.DeviceEnrollment
	tokenHash string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{devices: map[string]model.Device{}, deviceSecrets: map[string]string{}, deviceEnrollments: map[string]memoryEnrollment{}, customerSecrets: map[string]string{}, rules: map[string]model.Rule{}, subscriptions: map[string]memorySubscription{}, subscriptionNodes: map[string][]model.Node{}, customerNodePrefs: map[string]map[string]string{}, commands: map[string]model.Command{}, nextNumber: 1}
}

func (s *MemoryStore) RegisterDevice(_ context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.Serial == serial {
			return model.Device{}, "", ErrAlreadyRegistered
		}
	}
	now := time.Now().UTC()
	d := model.Device{ID: identity.NewID(), DeviceNumber: s.nextNumber, Serial: serial, MAC: mac, State: model.DevicePending, Online: true, LastSeen: &now, LastIP: in.IP, FirmwareVersion: in.FirmwareVersion, AgentVersion: in.AgentVersion, KernelVersion: in.KernelVersion, HardwareVersion: in.HardwareVersion, Profile: "gfw_precise", ConfigVersion: 1, CreatedAt: now, UpdatedAt: now}
	secret := identity.NewSecret()
	s.devices[d.ID] = d
	s.deviceSecrets[d.ID] = auth.SecretHash(secret)
	s.nextNumber++
	return d, secret, nil
}

func (s *MemoryStore) GetDevice(_ context.Context, id string) (model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	if expireOverride(&d, time.Now().UTC()) {
		s.devices[id] = d
	}
	return d, nil
}

func (s *MemoryStore) GetDeviceAuth(_ context.Context, id string) (model.DeviceAuth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	if !ok {
		return model.DeviceAuth{}, ErrNotFound
	}
	return model.DeviceAuth{ID: d.ID, Serial: d.Serial, SecretHash: s.deviceSecrets[id], State: d.State}, nil
}

func (s *MemoryStore) GetCustomerAuthBySerial(_ context.Context, serial string) (model.CustomerAuth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.devices {
		if d.Serial == serial {
			return model.CustomerAuth{ID: d.ID, Serial: d.Serial, CustomerAccessHash: s.customerSecrets[d.ID], State: d.State, Version: d.CustomerSessionVersion}, nil
		}
	}
	return model.CustomerAuth{}, ErrNotFound
}

func (s *MemoryStore) RotateCustomerAccess(_ context.Context, id string) (model.Device, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, "", ErrNotFound
	}
	token := identity.NewSecret()
	s.customerSecrets[id] = auth.SecretHash(token)
	d.CustomerSessionVersion++
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[id] = d
	return d, token, nil
}

func (s *MemoryStore) ListDevices(_ context.Context, offlineAfter time.Duration) ([]model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	result := make([]model.Device, 0, len(s.devices))
	for _, d := range s.devices {
		d.Online = d.LastSeen != nil && now.Sub(*d.LastSeen) <= offlineAfter && d.State != model.DeviceDisabled
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DeviceNumber < result[j].DeviceNumber })
	return result, nil
}

func (s *MemoryStore) SetRescueSSHPort(_ context.Context, id string, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return ErrNotFound
	}
	if port < 0 || port > 65535 {
		return errors.New("invalid rescue SSH port")
	}
	if port != 0 {
		for otherID, other := range s.devices {
			if otherID != id && other.RescueSSHPort == port {
				return ErrConflict
			}
		}
	}
	d.RescueSSHPort = port
	s.devices[id] = d
	return nil
}

// AllocateRescueSSHPort assigns the lowest currently unused port while
// holding the store lock. The existing assignment is sticky so a retry or a
// duplicate registration never moves a device to another public port.
func (s *MemoryStore) AllocateRescueSSHPort(_ context.Context, id string, start, end int) (int, error) {
	if start < 1 || end < start || end > 65535 {
		return 0, errors.New("invalid rescue SSH port range")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return 0, ErrNotFound
	}
	if d.RescueSSHPort > 0 {
		return d.RescueSSHPort, nil
	}
	used := make(map[int]struct{}, len(s.devices))
	for _, other := range s.devices {
		if other.RescueSSHPort > 0 {
			used[other.RescueSSHPort] = struct{}{}
		}
	}
	for port := start; port <= end; port++ {
		if _, exists := used[port]; exists {
			continue
		}
		d.RescueSSHPort = port
		d.UpdatedAt = time.Now().UTC()
		s.devices[id] = d
		return port, nil
	}
	return 0, ErrLimit
}

func (s *MemoryStore) UpdateDevice(_ context.Context, id string, state model.DeviceState, note, profile string) (model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	if state != "" {
		if state != d.State {
			d.CustomerSessionVersion++
		}
		d.State = state
	}
	d.Note = note
	if profile != "" {
		d.Profile = profile
	}
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[id] = d
	return d, nil
}

func (s *MemoryStore) SetCustomerOverride(_ context.Context, id, action string, until *time.Time) (model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	d.CustomerOverrideAction, d.CustomerOverrideUntil = action, until
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[id] = d
	return d, nil
}

func (s *MemoryStore) ListCustomerRules(_ context.Context, deviceID string) ([]model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Rule, 0)
	for _, r := range s.rules {
		if r.DeviceID == deviceID && r.SourceType == "user" && r.Source == "customer" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

func (s *MemoryStore) DeleteRuleForDevice(_ context.Context, id, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok || r.DeviceID != deviceID || r.SourceType != "user" || r.Source != "customer" {
		return ErrNotFound
	}
	delete(s.rules, id)
	d := s.devices[deviceID]
	d.ConfigVersion++
	s.devices[deviceID] = d
	return nil
}

func (s *MemoryStore) SetCustomerNodePreference(_ context.Context, deviceID, category, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok || !selection.Valid(nodeID, s.subscriptionNodes[d.SubscriptionID]) {
		return ErrNotFound
	}
	if s.customerNodePrefs[deviceID] == nil {
		s.customerNodePrefs[deviceID] = map[string]string{}
	}
	if nodeID == "" {
		delete(s.customerNodePrefs[deviceID], category)
	} else {
		s.customerNodePrefs[deviceID][category] = nodeID
	}
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[deviceID] = d
	return nil
}

func (s *MemoryStore) ListCustomerNodePreferences(_ context.Context, deviceID string) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.devices[deviceID]; !ok {
		return nil, ErrNotFound
	}
	out := map[string]string{}
	for category, nodeID := range s.customerNodePrefs[deviceID] {
		if selection.Valid(nodeID, s.subscriptionNodes[s.devices[deviceID].SubscriptionID]) {
			out[category] = nodeID
		}
	}
	return out, nil
}

func (s *MemoryStore) Heartbeat(_ context.Context, id string, r model.DeviceReport) (model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, ErrNotFound
	}
	now := time.Now().UTC()
	d.LastSeen, d.UpdatedAt, d.Online = &now, now, true
	if r.IP != "" {
		d.LastIP = r.IP
	}
	if r.FirmwareVersion != "" {
		d.FirmwareVersion = r.FirmwareVersion
	}
	if r.AgentVersion != "" {
		d.AgentVersion = r.AgentVersion
	}
	if r.KernelVersion != "" {
		d.KernelVersion = r.KernelVersion
	}
	if r.HardwareVersion != "" {
		d.HardwareVersion = r.HardwareVersion
	}
	s.devices[id] = d
	return d, nil
}

func (s *MemoryStore) ListRules(_ context.Context, deviceID string) ([]model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.Rule, 0)
	for _, r := range s.rules {
		if r.DeviceID == "" || r.DeviceID == deviceID || r.SourceType == "provider" {
			result = append(result, r)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Priority < result[j].Priority })
	return result, nil
}

func (s *MemoryStore) CreateRule(_ context.Context, r model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = identity.NewID()
	}
	r.Source = defaultString(r.Source, "user")
	r.SourceType = defaultString(r.SourceType, "user")
	if !r.Enabled {
		r.Enabled = true
	}
	s.rules[r.ID] = r
	for id, d := range s.devices {
		if r.DeviceID == "" || r.DeviceID == id {
			d.ConfigVersion++
			s.devices[id] = d
		}
	}
	return r, nil
}

func (s *MemoryStore) DeleteRule(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.rules, id)
	for key, d := range s.devices {
		if r.DeviceID == "" || r.DeviceID == key {
			d.ConfigVersion++
			s.devices[key] = d
		}
	}
	return nil
}

func (s *MemoryStore) ReplaceProviderRules(_ context.Context, source string, rules []model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.rules {
		if r.SourceType == "provider" && r.Source == source {
			delete(s.rules, id)
		}
	}
	for _, r := range rules {
		if r.ID == "" {
			r.ID = identity.NewID()
		}
		r.Source, r.SourceType, r.Enabled = source, "provider", true
		s.rules[r.ID] = r
	}
	for id, d := range s.devices {
		d.ConfigVersion++
		s.devices[id] = d
	}
	return nil
}

func (s *MemoryStore) createSubscription(name, provider string, ciphertext []byte, lookup string) (model.SubscriptionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.subscriptions {
		if lookup != "" && sub.lookup == lookup {
			return model.SubscriptionView{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	v := model.SubscriptionView{ID: identity.NewID(), Name: name, Provider: provider, Status: "pending", CreatedAt: now, UpdatedAt: now}
	s.subscriptions[v.ID] = memorySubscription{SubscriptionView: v, ciphertext: append([]byte(nil), ciphertext...), lookup: lookup}
	return v, nil
}

func (s *MemoryStore) CreateSubscription(_ context.Context, name, provider string, ciphertext []byte, lookup ...string) (model.SubscriptionView, error) {
	key := ""
	if len(lookup) > 0 {
		key = lookup[0]
	}
	return s.createSubscription(name, provider, ciphertext, key)
}

func (s *MemoryStore) ListSubscriptions(_ context.Context) ([]model.SubscriptionView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.SubscriptionView, 0, len(s.subscriptions))
	for _, sub := range s.subscriptions {
		result = append(result, sub.SubscriptionView)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

func (s *MemoryStore) DeleteSubscription(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subscriptions[id]; !ok {
		return 0, ErrNotFound
	}
	for mac, enrollment := range s.deviceEnrollments {
		if enrollment.SubscriptionID == id {
			enrollment.SubscriptionID = ""
			s.deviceEnrollments[mac] = enrollment
		}
	}
	now := time.Now().UTC()
	detached := 0
	for deviceID, device := range s.devices {
		if device.SubscriptionID != id {
			continue
		}
		device.SubscriptionID = ""
		device.ConfigVersion++
		device.UpdatedAt = now
		s.devices[deviceID] = device
		delete(s.customerNodePrefs, deviceID)
		detached++
	}
	delete(s.subscriptionNodes, id)
	delete(s.subscriptions, id)
	return detached, nil
}

func (s *MemoryStore) GetSubscriptionCiphertext(_ context.Context, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subscriptions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), sub.ciphertext...), nil
}

func (s *MemoryStore) FindSubscriptionByLookup(_ context.Context, lookup string) (model.SubscriptionView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.subscriptions {
		if lookup != "" && sub.lookup == lookup {
			return sub.SubscriptionView, nil
		}
	}
	return model.SubscriptionView{}, ErrNotFound
}

func (s *MemoryStore) UpdateSubscriptionStatus(_ context.Context, id, status string, nodeCount int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.subscriptions[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	sub.Status, sub.UpdatedAt = status, now
	if nodeCount >= 0 {
		sub.NodeCount, sub.LastRefresh = nodeCount, &now
	}
	s.subscriptions[id] = sub
	return nil
}

func (s *MemoryStore) GetSubscriptionNodes(_ context.Context, id string) ([]model.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.subscriptions[id]; !ok {
		return nil, ErrNotFound
	}
	return append([]model.Node(nil), s.subscriptionNodes[id]...), nil
}
func (s *MemoryStore) ReplaceSubscriptionNodes(_ context.Context, id string, nodes []model.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subscriptions[id]; !ok {
		return ErrNotFound
	}
	s.subscriptionNodes[id] = append([]model.Node(nil), nodes...)
	for key, d := range s.devices {
		if d.SubscriptionID == id {
			d.ConfigVersion++
			s.devices[key] = d
			for category, node := range s.customerNodePrefs[key] {
				if !selection.Valid(node, nodes) {
					delete(s.customerNodePrefs[key], category)
				}
			}
		}
	}
	return nil
}

func (s *MemoryStore) CommitValidatedNodes(_ context.Context, deviceID, subscriptionID string, nodes []model.CustomerNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok || d.SubscriptionID != subscriptionID {
		return ErrConflict
	}
	sub, ok := s.subscriptions[subscriptionID]
	if !ok {
		return ErrNotFound
	}
	current := s.subscriptionNodes[subscriptionID]
	unchanged := len(current) == len(nodes)
	if unchanged {
		byID := make(map[string]string, len(current))
		for _, node := range current {
			if node.Protocol != "dae" || node.Server != "" || node.Port != 0 || node.Group != "" || len(node.Params) != 0 {
				unchanged = false
			}
			byID[node.ID] = node.Name
		}
		for _, node := range nodes {
			if byID[node.ID] != node.Name {
				unchanged = false
				break
			}
		}
	}
	if !unchanged {
		replacement := make([]model.Node, 0, len(nodes))
		for _, node := range nodes {
			replacement = append(replacement, model.Node{ID: node.ID, Name: node.Name, Protocol: "dae"})
		}
		s.subscriptionNodes[subscriptionID] = replacement
		for category, nodeID := range s.customerNodePrefs[deviceID] {
			if !selection.Valid(nodeID, replacement) {
				delete(s.customerNodePrefs[deviceID], category)
			}
		}
		d.ConfigVersion++
		s.devices[deviceID] = d
	}
	now := time.Now().UTC()
	sub.Status, sub.NodeCount, sub.LastRefresh, sub.UpdatedAt = "ok", len(nodes), &now, now
	s.subscriptions[subscriptionID] = sub
	return nil
}

func (s *MemoryStore) BindSubscription(_ context.Context, deviceID, subscriptionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := s.subscriptions[subscriptionID]; !ok {
		return ErrNotFound
	}
	if s.subscriptionReserved(subscriptionID) {
		return ErrConflict
	}
	for id, other := range s.devices {
		if id != deviceID && other.SubscriptionID == subscriptionID {
			return ErrConflict
		}
	}
	if d.SubscriptionID != subscriptionID {
		delete(s.customerNodePrefs, deviceID)
	}
	d.SubscriptionID = subscriptionID
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[deviceID] = d
	return nil
}

func (s *MemoryStore) EnqueueCommand(_ context.Context, c model.Command) (model.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[c.DeviceID]; !ok {
		return c, ErrNotFound
	}
	count := 0
	for id, old := range s.commands {
		if old.DeviceID == c.DeviceID {
			if old.Status != "queued" && old.Status != "claimed" && time.Since(old.CreatedAt) > 24*time.Hour {
				delete(s.commands, id)
				continue
			}
			count++
			if isSoftwareCommand(c.Command) && isSoftwareCommand(old.Command) && (old.Status == "queued" || old.Status == "claimed") {
				return c, ErrConflict
			}
			if (old.Status == "queued" || old.Status == "claimed") && old.Command == c.Command && old.Payload == c.Payload {
				return old, nil
			}
		}
	}
	if count >= 100 {
		return c, ErrLimit
	}
	if c.ID == "" {
		c.ID = identity.NewID()
	}
	c.Status = "queued"
	c.CreatedAt = time.Now().UTC()
	s.commands[c.ID] = c
	return c, nil
}
func (s *MemoryStore) ListDeviceCommands(_ context.Context, deviceID string) ([]model.Command, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.devices[deviceID]; !ok {
		return nil, ErrNotFound
	}
	out := []model.Command{}
	for _, command := range s.commands {
		if command.DeviceID == deviceID && (command.Command == "software_update" || command.Command == "software_rollback") {
			out = append(out, command)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > 10 {
		out = out[:10]
	}
	return out, nil
}
func (s *MemoryStore) PollCommands(_ context.Context, deviceID string) ([]model.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []model.Command{}
	now := time.Now().UTC()
	for id, c := range s.commands {
		if c.DeviceID == deviceID && (c.Status == "queued" || (c.Status == "claimed" && c.ClaimedAt != nil && time.Since(*c.ClaimedAt) > time.Minute)) {
			c.Status, c.ClaimedAt = "claimed", &now
			s.commands[id] = c
			result = append(result, c)
		}
	}
	return result, nil
}
func (s *MemoryStore) AckCommand(_ context.Context, deviceID, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.commands[id]
	if !ok || c.DeviceID != deviceID || (c.Status != "claimed" && c.Status != status) {
		return ErrNotFound
	}
	now := time.Now().UTC()
	c.Status, c.AckedAt = status, &now
	s.commands[id] = c
	return nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type SQLStore struct{ db *sql.DB }

func OpenMySQL(dsn string) (*SQLStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &SQLStore{db: db}, nil
}
func (s *SQLStore) Close() error                   { return s.db.Close() }
func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLStore) RegisterDevice(ctx context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	id, secret := identity.NewID(), identity.NewSecret()
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices (id, serial, mac, secret_hash, state, online, last_seen, last_ip, firmware_version, agent_version, kernel_version, hardware_version, profile, config_version, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', 1, ?, ?, ?, ?, ?, ?, 'gfw_precise', 1, ?, ?)`, id, serial, mac, auth.SecretHash(secret), now, in.IP, in.FirmwareVersion, in.AgentVersion, in.KernelVersion, in.HardwareVersion, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.Device{}, "", ErrAlreadyRegistered
		}
		return model.Device{}, "", err
	}
	d, err := s.GetDevice(ctx, id)
	return d, secret, err
}

func scanDevice(scanner interface{ Scan(...any) error }) (model.Device, error) {
	var d model.Device
	var lastSeen sql.NullTime
	var sub sql.NullString
	var overrideAction sql.NullString
	var overrideUntil sql.NullTime
	var rescuePort sql.NullInt64
	err := scanner.Scan(&d.ID, &d.DeviceNumber, &d.Serial, &d.MAC, &d.Note, &d.State, &d.Online, &lastSeen, &d.LastIP, &d.FirmwareVersion, &d.AgentVersion, &d.KernelVersion, &d.HardwareVersion, &d.Profile, &d.ConfigVersion, &sub, &d.CreatedAt, &d.UpdatedAt, &d.Name, &d.Email, &overrideAction, &overrideUntil, &d.CustomerSessionVersion, &rescuePort)
	if err != nil {
		return model.Device{}, err
	}
	if lastSeen.Valid {
		d.LastSeen = &lastSeen.Time
	}
	if sub.Valid {
		d.SubscriptionID = sub.String
	}
	if overrideAction.Valid {
		d.CustomerOverrideAction = overrideAction.String
	}
	if overrideUntil.Valid {
		d.CustomerOverrideUntil = &overrideUntil.Time
	}
	if rescuePort.Valid {
		d.RescueSSHPort = int(rescuePort.Int64)
	}
	return d, nil
}

const deviceColumns = `id, device_number, serial, mac, note, state, online, last_seen, last_ip, firmware_version, agent_version, kernel_version, hardware_version, profile, config_version, subscription_id, created_at, updated_at, name, COALESCE(email,''), COALESCE(customer_override_action,''), customer_override_until, customer_session_version, rescue_ssh_port`

func (s *SQLStore) GetDevice(ctx context.Context, id string) (model.Device, error) {
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET customer_override_action='',customer_override_until=NULL,config_version=config_version+1 WHERE id=? AND customer_override_action<>'' AND customer_override_until<=UTC_TIMESTAMP(6)`, id); err != nil {
		return model.Device{}, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, ErrNotFound
	}
	return d, err
}
func (s *SQLStore) GetDeviceAuth(ctx context.Context, id string) (model.DeviceAuth, error) {
	var a model.DeviceAuth
	err := s.db.QueryRowContext(ctx, `SELECT id, serial, secret_hash, state FROM devices WHERE id = ?`, id).Scan(&a.ID, &a.Serial, &a.SecretHash, &a.State)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) GetCustomerAuthBySerial(ctx context.Context, serial string) (model.CustomerAuth, error) {
	var a model.CustomerAuth
	err := s.db.QueryRowContext(ctx, `SELECT id,serial,COALESCE(customer_access_hash,''),state,customer_session_version FROM devices WHERE serial=?`, serial).Scan(&a.ID, &a.Serial, &a.CustomerAccessHash, &a.State, &a.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) RotateCustomerAccess(ctx context.Context, id string) (model.Device, string, error) {
	token := identity.NewSecret()
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET customer_access_hash=?,customer_session_version=customer_session_version+1,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, auth.SecretHash(token), id)
	if err != nil {
		return model.Device{}, "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Device{}, "", ErrNotFound
	}
	d, err := s.GetDevice(ctx, id)
	return d, token, err
}
func (s *SQLStore) ListDevices(ctx context.Context, offlineAfter time.Duration) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices ORDER BY device_number`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Device, 0)
	cutoff := time.Now().UTC().Add(-offlineAfter)
	for rows.Next() {
		d, e := scanDevice(rows)
		if e != nil {
			return nil, e
		}
		d.Online = d.State != model.DeviceDisabled && d.LastSeen != nil && d.LastSeen.After(cutoff)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) SetRescueSSHPort(ctx context.Context, id string, port int) error {
	if port < 0 || port > 65535 {
		return errors.New("invalid rescue SSH port")
	}
	if _, err := s.GetDevice(ctx, id); err != nil {
		return err
	}
	var value any
	if port != 0 {
		value = port
	}
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET rescue_ssh_port=?, updated_at=UTC_TIMESTAMP(6) WHERE id=?`, value, id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return ErrConflict
		}
		return err
	}
	return nil
}

// AllocateRescueSSHPort uses the unique database index as the concurrency
// boundary. Competing cloud instances may try the same candidate, but only
// one can claim it; the loser advances to the next candidate. The assignment
// is sticky once written.
func (s *SQLStore) AllocateRescueSSHPort(ctx context.Context, id string, start, end int) (int, error) {
	if start < 1 || end < start || end > 65535 {
		return 0, errors.New("invalid rescue SSH port range")
	}
	d, err := s.GetDevice(ctx, id)
	if err != nil {
		return 0, err
	}
	if d.RescueSSHPort > 0 {
		return d.RescueSSHPort, nil
	}
	for port := start; port <= end; port++ {
		res, err := s.db.ExecContext(ctx, `UPDATE devices SET rescue_ssh_port=?, updated_at=UTC_TIMESTAMP(6) WHERE id=? AND rescue_ssh_port IS NULL`, port, id)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				continue
			}
			return 0, err
		}
		rows, _ := res.RowsAffected()
		if rows == 1 {
			return port, nil
		}
		// Another request may have won the race for this same device.
		current, getErr := s.GetDevice(ctx, id)
		if getErr != nil {
			return 0, getErr
		}
		if current.RescueSSHPort > 0 {
			return current.RescueSSHPort, nil
		}
	}
	return 0, ErrLimit
}
func (s *SQLStore) UpdateDevice(ctx context.Context, id string, state model.DeviceState, note, profile string) (model.Device, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET customer_session_version=customer_session_version+IF(?<>'' AND ?<>state,1,0),state=COALESCE(NULLIF(?,''),state), note=?, profile=COALESCE(NULLIF(?,''),profile), config_version=config_version+1, updated_at=UTC_TIMESTAMP() WHERE id=?`, state, state, state, note, profile, id)
	if err != nil {
		return model.Device{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Device{}, ErrNotFound
	}
	return s.GetDevice(ctx, id)
}

func (s *SQLStore) SetCustomerOverride(ctx context.Context, id, action string, until *time.Time) (model.Device, error) {
	var expiry any
	if until != nil {
		expiry = *until
	}
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET customer_override_action=?,customer_override_until=?,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, action, expiry, id)
	if err != nil {
		return model.Device{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Device{}, ErrNotFound
	}
	return s.GetDevice(ctx, id)
}

func (s *SQLStore) ListCustomerRules(ctx context.Context, deviceID string) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source,source_type,category,match_type,match_value,action,priority,enabled,COALESCE(device_id,''),COALESCE(source_ip,''),COALESCE(source_mac,'') FROM rules WHERE device_id=? AND source_type='user' AND source='customer' ORDER BY priority,id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Rule, 0)
	for rows.Next() {
		var r model.Rule
		if err := rows.Scan(&r.ID, &r.Source, &r.SourceType, &r.Category, &r.MatchType, &r.MatchValue, &r.Action, &r.Priority, &r.Enabled, &r.DeviceID, &r.SourceIP, &r.SourceMAC); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteRuleForDevice(ctx context.Context, id, deviceID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1 WHERE id=?`, deviceID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM rules WHERE id=? AND device_id=? AND source_type='user' AND source='customer'`, id, deviceID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) SetCustomerNodePreference(ctx context.Context, deviceID, category, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sub string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, deviceID).Scan(&sub); err != nil {
		return err
	}
	if nodeID == "" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM customer_node_preferences WHERE device_id=? AND category=?`, deviceID, category); err != nil {
			return err
		}
	} else {
		rows, queryErr := tx.QueryContext(ctx, `SELECT id,name FROM subscription_nodes WHERE subscription_id=?`, sub)
		if queryErr != nil {
			return queryErr
		}
		available := []model.Node{}
		for rows.Next() {
			var node model.Node
			if err = rows.Scan(&node.ID, &node.Name); err != nil {
				rows.Close()
				return err
			}
			available = append(available, node)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !selection.Valid(nodeID, available) {
			return ErrNotFound
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO customer_node_preferences(device_id,category,node_id,updated_at) VALUES (?,?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE node_id=VALUES(node_id),updated_at=VALUES(updated_at)`, deviceID, category, nodeID); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, deviceID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) ListCustomerNodePreferences(ctx context.Context, deviceID string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT category,node_id FROM customer_node_preferences WHERE device_id=?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var category, nodeID string
		if err := rows.Scan(&category, &nodeID); err != nil {
			return nil, err
		}
		out[category] = nodeID
	}
	return out, rows.Err()
}
func (s *SQLStore) Heartbeat(ctx context.Context, id string, r model.DeviceReport) (model.Device, error) {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET online=1,last_seen=UTC_TIMESTAMP(6),last_ip=COALESCE(NULLIF(?,''),last_ip),firmware_version=COALESCE(NULLIF(?,''),firmware_version),agent_version=COALESCE(NULLIF(?,''),agent_version),kernel_version=COALESCE(NULLIF(?,''),kernel_version),hardware_version=COALESCE(NULLIF(?,''),hardware_version),updated_at=UTC_TIMESTAMP(6) WHERE id=?`, r.IP, r.FirmwareVersion, r.AgentVersion, r.KernelVersion, r.HardwareVersion, id)
	if err != nil {
		return model.Device{}, err
	}
	// MySQL changed-rows=0 also means an existing row already has these
	// values. The read distinguishes a missing device without false failures.
	return s.GetDevice(ctx, id)
}
func (s *SQLStore) ListRules(ctx context.Context, deviceID string) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source,source_type,category,match_type,match_value,action,priority,enabled,COALESCE(device_id,''),COALESCE(source_ip,''),COALESCE(source_mac,'') FROM rules WHERE enabled=1 AND (device_id IS NULL OR device_id='' OR device_id=? OR source_type='provider') ORDER BY priority,id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Rule, 0)
	for rows.Next() {
		var r model.Rule
		if err := rows.Scan(&r.ID, &r.Source, &r.SourceType, &r.Category, &r.MatchType, &r.MatchValue, &r.Action, &r.Priority, &r.Enabled, &r.DeviceID, &r.SourceIP, &r.SourceMAC); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *SQLStore) CreateRule(ctx context.Context, r model.Rule) (model.Rule, error) {
	if r.ID == "" {
		r.ID = identity.NewID()
	}
	r.Source = defaultString(r.Source, "user")
	r.SourceType = defaultString(r.SourceType, "user")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1 WHERE ?='' OR id=?`, r.DeviceID, r.DeviceID); err != nil {
		return r, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO rules (id,source,source_type,category,match_type,match_value,action,priority,enabled,device_id,source_ip,source_mac) VALUES (?,?,?,?,?,?,?,?,?,NULLIF(?,''),?,?)`, r.ID, r.Source, r.SourceType, r.Category, r.MatchType, r.MatchValue, r.Action, r.Priority, r.Enabled, r.DeviceID, r.SourceIP, r.SourceMAC)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *SQLStore) DeleteRule(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Admin deletion is rare; lock/version all devices to preserve lock ordering.
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1`); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}
func (s *SQLStore) ReplaceProviderRules(ctx context.Context, source string, rules []model.Rule) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM rules WHERE source_type='provider' AND source=?`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, r := range rules {
		if r.ID == "" {
			r.ID = identity.NewID()
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO rules (id,source,source_type,category,match_type,match_value,action,priority,enabled,device_id,source_ip,source_mac) VALUES (?,?,?,?,?,?,?,?,?,NULLIF(?,''),?,?)`, r.ID, source, "provider", r.Category, r.MatchType, r.MatchValue, r.Action, r.Priority, true, r.DeviceID, r.SourceIP, r.SourceMAC); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLStore) CreateSubscription(ctx context.Context, name, provider string, ciphertext []byte, lookup ...string) (model.SubscriptionView, error) {
	id := identity.NewID()
	now := time.Now().UTC()
	key := ""
	if len(lookup) > 0 {
		key = lookup[0]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO subscriptions (id,name,provider,url_ciphertext,status,node_count,created_at,updated_at,url_lookup) VALUES (?,?,?,?, 'pending',0,?,?,NULLIF(?,''))`, id, name, provider, ciphertext, now, now, key)
	if err != nil {
		return model.SubscriptionView{}, identityError(err)
	}
	return s.subscriptionView(ctx, id)
}
func (s *SQLStore) subscriptionView(ctx context.Context, id string) (model.SubscriptionView, error) {
	var v model.SubscriptionView
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,name,provider,status,node_count,last_refresh,created_at,updated_at FROM subscriptions WHERE id=?`, id).Scan(&v.ID, &v.Name, &v.Provider, &v.Status, &v.NodeCount, &last, &v.CreatedAt, &v.UpdatedAt)
	if last.Valid {
		v.LastRefresh = &last.Time
	}
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
func (s *SQLStore) ListSubscriptions(ctx context.Context) ([]model.SubscriptionView, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,provider,status,node_count,last_refresh,created_at,updated_at FROM subscriptions ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.SubscriptionView, 0)
	for rows.Next() {
		var v model.SubscriptionView
		var last sql.NullTime
		if err := rows.Scan(&v.ID, &v.Name, &v.Provider, &v.Status, &v.NodeCount, &last, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			v.LastRefresh = &last.Time
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteSubscription(ctx context.Context, id string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT id FROM devices WHERE subscription_id=? FOR UPDATE`, id)
	if err != nil {
		return 0, err
	}
	deviceIDs := make([]string, 0, 1)
	for rows.Next() {
		var deviceID string
		if err = rows.Scan(&deviceID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}

	for _, deviceID := range deviceIDs {
		if _, err = tx.ExecContext(ctx, `DELETE FROM customer_node_preferences WHERE device_id=?`, deviceID); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE devices SET subscription_id=NULL,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND subscription_id=?`, deviceID, id); err != nil {
			return 0, err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM subscriptions WHERE id=?`, id)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleted == 0 {
		return 0, ErrNotFound
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(deviceIDs), nil
}
func (s *SQLStore) GetSubscriptionCiphertext(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT url_ciphertext FROM subscriptions WHERE id=?`, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *SQLStore) FindSubscriptionByLookup(ctx context.Context, lookup string) (model.SubscriptionView, error) {
	var v model.SubscriptionView
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id,name,provider,status,node_count,last_refresh,created_at,updated_at FROM subscriptions WHERE url_lookup=?`, lookup).Scan(&v.ID, &v.Name, &v.Provider, &v.Status, &v.NodeCount, &last, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if last.Valid {
		v.LastRefresh = &last.Time
	}
	return v, err
}
func (s *SQLStore) UpdateSubscriptionStatus(ctx context.Context, id, status string, nodeCount int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE subscriptions SET status=?,node_count=IF(?<0,node_count,?),last_refresh=IF(?<0,last_refresh,UTC_TIMESTAMP(6)),updated_at=UTC_TIMESTAMP(6) WHERE id=?`, status, nodeCount, nodeCount, nodeCount, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *SQLStore) GetSubscriptionNodes(ctx context.Context, id string) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,protocol,server,port,region,group_name,params_json FROM subscription_nodes WHERE subscription_id=? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Node, 0)
	for rows.Next() {
		var n model.Node
		var params string
		if err := rows.Scan(&n.ID, &n.Name, &n.Protocol, &n.Server, &n.Port, &n.Region, &n.Group, &params); err != nil {
			return nil, err
		}
		n.Params = map[string]string{}
		if params != "" {
			_ = json.Unmarshal([]byte(params), &n.Params)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *SQLStore) ReplaceSubscriptionNodes(ctx context.Context, id string, nodes []model.Node) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1 WHERE subscription_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_nodes WHERE subscription_id=?`, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, n := range nodes {
		b, _ := json.Marshal(n.Params)
		if _, err = tx.ExecContext(ctx, `INSERT INTO subscription_nodes (id,subscription_id,name,protocol,server,port,region,group_name,params_json) VALUES (?,?,?,?,?,?,?,?,?)`, n.ID, id, n.Name, n.Protocol, n.Server, n.Port, n.Region, n.Group, string(b)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE p FROM customer_node_preferences p JOIN devices d ON d.id=p.device_id LEFT JOIN subscription_nodes n ON n.subscription_id=d.subscription_id AND n.id=p.node_id WHERE d.subscription_id=? AND n.id IS NULL AND p.node_id NOT IN ('@direct','@proxy') AND p.node_id NOT LIKE '@region:%' AND p.node_id NOT LIKE '@failover:%'`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CommitValidatedNodes(ctx context.Context, deviceID, subscriptionID string, nodes []model.CustomerNode) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var bound string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, deviceID).Scan(&bound); err != nil {
		return err
	}
	if bound != subscriptionID {
		return ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,name,protocol,server,port,group_name FROM subscription_nodes WHERE subscription_id=? FOR UPDATE`, subscriptionID)
	if err != nil {
		return err
	}
	current := make(map[string]string, len(nodes))
	legacySensitiveRows := false
	for rows.Next() {
		var id, name, protocol, server, group string
		var port int
		if err = rows.Scan(&id, &name, &protocol, &server, &port, &group); err != nil {
			rows.Close()
			return err
		}
		if protocol != "dae" || server != "" || port != 0 || group != "" {
			legacySensitiveRows = true
		}
		current[id] = name
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	unchanged := len(current) == len(nodes) && !legacySensitiveRows
	for _, node := range nodes {
		if current[node.ID] != node.Name {
			unchanged = false
			break
		}
	}
	if !unchanged {
		if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_nodes WHERE subscription_id=?`, subscriptionID); err != nil {
			return err
		}
		for _, node := range nodes {
			if _, err = tx.ExecContext(ctx, `INSERT INTO subscription_nodes(id,subscription_id,name,protocol,server,port,region,group_name,params_json) VALUES (?,?,?,'dae','',0,'','','{}')`, node.ID, subscriptionID, node.Name); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `DELETE p FROM customer_node_preferences p LEFT JOIN subscription_nodes n ON n.subscription_id=? AND n.id=p.node_id WHERE p.device_id=? AND n.id IS NULL AND p.node_id NOT IN ('@direct','@proxy') AND p.node_id NOT LIKE '@region:%' AND p.node_id NOT LIKE '@failover:%'`, subscriptionID, deviceID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, deviceID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET status='ok',node_count=?,last_refresh=UTC_TIMESTAMP(6),updated_at=UTC_TIMESTAMP(6) WHERE id=?`, len(nodes), subscriptionID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *SQLStore) BindSubscription(ctx context.Context, deviceID, subscriptionID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkSubscriptionReservation(ctx, tx, subscriptionID); err != nil {
		return err
	}
	var oldSub string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, deviceID).Scan(&oldSub); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE devices SET subscription_id=?,config_version=config_version+1,updated_at=UTC_TIMESTAMP() WHERE id=?`, subscriptionID, deviceID)
	if err != nil {
		return identityError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if oldSub != subscriptionID {
		if _, err = tx.ExecContext(ctx, `DELETE FROM customer_node_preferences WHERE device_id=?`, deviceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLStore) EnqueueCommand(ctx context.Context, c model.Command) (model.Command, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE id=? FOR UPDATE`, c.DeviceID).Scan(&id); err != nil {
		return c, ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM commands WHERE device_id=? AND status NOT IN ('queued','claimed') AND created_at<UTC_TIMESTAMP()-INTERVAL 1 DAY`, c.DeviceID); err != nil {
		return c, err
	}
	if isSoftwareCommand(c.Command) {
		var pendingID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM commands WHERE device_id=? AND command IN ('software_update','software_rollback') AND status IN ('queued','claimed') LIMIT 1`, c.DeviceID).Scan(&pendingID)
		if err == nil {
			return c, ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return c, err
		}
	}
	var old model.Command
	err = tx.QueryRowContext(ctx, `SELECT id,status,created_at FROM commands WHERE device_id=? AND command=? AND payload=? AND status IN ('queued','claimed') LIMIT 1`, c.DeviceID, c.Command, c.Payload).Scan(&old.ID, &old.Status, &old.CreatedAt)
	if err == nil {
		old.DeviceID = c.DeviceID
		old.Command = c.Command
		old.Payload = c.Payload
		return old, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return c, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM commands WHERE device_id=?`, c.DeviceID).Scan(&count); err != nil {
		return c, err
	}
	if count >= 100 {
		return c, ErrLimit
	}
	if c.ID == "" {
		c.ID = identity.NewID()
	}
	c.Status = "queued"
	c.CreatedAt = time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO commands (id,device_id,command,payload,status,created_at) VALUES (?,?,?,?,?,?)`, c.ID, c.DeviceID, c.Command, c.Payload, c.Status, c.CreatedAt)
	if err != nil {
		return c, err
	}
	return c, tx.Commit()
}
func isSoftwareCommand(command string) bool {
	return command == "software_update" || command == "software_rollback"
}
func (s *SQLStore) ListDeviceCommands(ctx context.Context, deviceID string) ([]model.Command, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,command,payload,status,created_at,claimed_at,acked_at FROM commands WHERE device_id=? AND command IN ('software_update','software_rollback') ORDER BY created_at DESC LIMIT 10`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Command{}
	for rows.Next() {
		var command model.Command
		var claimed, acked sql.NullTime
		if err := rows.Scan(&command.ID, &command.DeviceID, &command.Command, &command.Payload, &command.Status, &command.CreatedAt, &claimed, &acked); err != nil {
			return nil, err
		}
		if claimed.Valid {
			command.ClaimedAt = &claimed.Time
		}
		if acked.Valid {
			command.AckedAt = &acked.Time
		}
		out = append(out, command)
	}
	return out, rows.Err()
}
func (s *SQLStore) PollCommands(ctx context.Context, deviceID string) ([]model.Command, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,device_id,command,payload,created_at FROM commands WHERE device_id=? AND (status='queued' OR (status='claimed' AND claimed_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE))) ORDER BY created_at LIMIT 100 FOR UPDATE`, deviceID)
	if err != nil {
		return nil, err
	}
	out := []model.Command{}
	now := time.Now().UTC()
	for rows.Next() {
		var c model.Command
		if err = rows.Scan(&c.ID, &c.DeviceID, &c.Command, &c.Payload, &c.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		c.Status = "claimed"
		c.ClaimedAt = &now
		out = append(out, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, c := range out {
		if _, err = tx.ExecContext(ctx, `UPDATE commands SET status='claimed',claimed_at=? WHERE id=? AND device_id=?`, now, c.ID, deviceID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *SQLStore) AckCommand(ctx context.Context, deviceID, id, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE commands SET status=?,acked_at=UTC_TIMESTAMP(6) WHERE id=? AND device_id=? AND (status='claimed' OR status=?)`, status, id, deviceID, status)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

var _ Store = (*MemoryStore)(nil)
var _ Store = (*SQLStore)(nil)

func NewFromEnv(dsn string) (Store, ioCloser, error) {
	if strings.TrimSpace(dsn) == "" || dsn == "memory://" {
		return NewMemoryStore(), nil, nil
	}
	s, err := OpenMySQL(dsn)
	if err != nil {
		return nil, nil, err
	}
	return s, s, nil
}

type ioCloser interface{ Close() error }

func IsNotFound(err error) bool          { return errors.Is(err, ErrNotFound) }
func IsAlreadyRegistered(err error) bool { return errors.Is(err, ErrAlreadyRegistered) }
func ExplainDB(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T: %v", err, err)
}
