package nodeprobe

import (
	"net/netip"
	"testing"
	"time"
)

func TestProbeURLAndPinnedAddressValidation(t *testing.T) {
	for _, raw := range []string{DefaultURL, "https://www.gstatic.com/generate_204", "http://8.8.8.8:80/ping?mode=ok"} {
		if err := ValidateURL(raw); err != nil {
			t.Fatalf("valid URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"file:///etc/passwd", "https://user:secret@example.com", "http://127.0.0.1", "http://192.168.1.1", "http://100.64.1.1", "http://169.254.169.254", "http://[::1]", "http://example.com:22", "http://example.local", "http://example.com/#secret", "http://example.com,1.1.1.1", "http://example.com/\nlog_level: debug"} {
		if ValidateURL(raw) == nil {
			t.Fatalf("unsafe URL accepted: %q", raw)
		}
	}
	compiled, err := Compile(DefaultURL, netip.MustParseAddr("1.1.1.1"))
	if err != nil || ValidateCompiled(compiled) != nil {
		t.Fatal("compiled public target rejected")
	}
	if ValidateCompiled(DefaultURL+",10.0.0.1") == nil {
		t.Fatal("private pin accepted")
	}
}
func TestProbeParsesOnlyNativeIPv4HTTPLatency(t *testing.T) {
	at := time.Now().UTC()
	obs, ok := ParseMessage(`DEBU[2026-10-01 11:22:33] Connectivity Check avg_10=91ms last=74ms mov_avg=90ms network=tcp4 node="ALI-SGP(新加坡4)"`, at)
	if !ok || obs.Name != "ALI-SGP(新加坡4)" || obs.Status != "ok" || obs.LatencyMS == nil || *obs.LatencyMS != 74 || !obs.CheckedAt.Equal(at) {
		t.Fatalf("bad observation: %#v %v", obs, ok)
	}
	obs, ok = ParseMessage(`DEBU[time] Connectivity Check Failed err="secret-endpoint must not escape" network=tcp4 node="节点 空格 \"引号\""`, at)
	if !ok || obs.Name != `节点 空格 "引号"` || obs.Status != "failed" || obs.LatencyMS != nil {
		t.Fatalf("bad failure: %#v", obs)
	}
	for _, raw := range []string{`DEBU[time] Connectivity Check last=42ms network=tcp6 node=IPv6`, `DEBU[time] Connectivity Check last=42ms network=udp4 node=DNS`, `DEBU[time] Connectivity Check network=tcp4 node=no-duration`, `DEBU[time] Connectivity Check last=-3ms network=tcp4 node=bad`, `DEBU[time] Group "candidate" node list:`, `INFO[time] flow node=not-a-check`} {
		if _, ok := ParseMessage(raw, at); ok {
			t.Fatalf("non-result parsed: %s", raw)
		}
	}
}

func TestProbeParsesDevicePlainDebugFormat(t *testing.T) {
	at := time.Date(2026, 10, 2, 1, 4, 0, 0, time.UTC)
	// Sanitized device journal fixtures: this logger has no DEBU[time] prefix.
	for _, test := range []struct {
		raw  string
		name string
		ms   int64
	}{
		{`DEBUG Connectivity Check avg_10=151ms last=122ms mov_avg=139ms network=tcp4 node="测试香港"`, "测试香港", 122},
		{`DEBUG Connectivity Check avg_10=310ms last=304ms mov_avg=307ms network=tcp4 node="测试美国"`, "测试美国", 304},
		{"DEBUG\tConnectivity Check last=500µs network=tcp4 node=zero", "zero", 0},
		{`level=debug msg="Connectivity Check" last=46ms network=tcp4 node=structured`, "structured", 46},
	} {
		obs, ok := ParseMessage(test.raw, at)
		if !ok || obs.Name != test.name || obs.Status != "ok" || obs.LatencyMS == nil || *obs.LatencyMS != test.ms || !obs.CheckedAt.Equal(at) {
			t.Fatalf("device check rejected: %#v, %v", obs, ok)
		}
	}
	obs, ok := ParseMessage(`DEBUG Connectivity Check Failed err="private endpoint must not escape" network=tcp4 node="测试失败"`, at)
	if !ok || obs.Name != "测试失败" || obs.Status != "failed" || obs.LatencyMS != nil {
		t.Fatalf("device failure rejected: %#v, %v", obs, ok)
	}
}

func TestProbePlainDebugStillRejectsNonResults(t *testing.T) {
	at := time.Now().UTC()
	for _, raw := range []string{
		`DEBUG Connectivity Check last=42ms network=tcp6 node=v6`,
		`DEBUG Connectivity Check last=42ms network=udp4(DNS) node=dns`,
		`DEBUG Connectivity Check network=tcp4 node=missing`,
		`DEBUG Connectivity Check last=-1ms network=tcp4 node=negative`,
		`DEBUG Connectivity Check last=11m network=tcp4 node=too-long`,
		`INFO Connectivity Check last=42ms network=tcp4 node=not-debug`,
		`flow DEBUG Connectivity Check last=42ms network=tcp4 node=traffic`,
		`DEBUG Group candidate node list: network=tcp4 node=candidate`,
	} {
		if _, ok := ParseMessage(raw, at); ok {
			t.Fatalf("non-HTTP-check accepted: %s", raw)
		}
	}
}
