package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"tygateway/internal/model"
	"tygateway/internal/rules"
)

var packageNames = map[string]string{"managed_loyal": "Loyalsoldier 综合分流", "managed_meta": "MetaCubeX 综合分流", "managed_gfw": "GFWList + 服务分类", "managed_geo": "GeoIP + 服务分类"}

var managedRuleAgentVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z0-9][A-Za-z0-9.-]*)?$`)

// Managed rule packages were introduced in 0.6.0. A newer minor or major
// release must not be rejected merely because it no longer starts with 0.6.
func supportsManagedRulePackages(agentVersion string) bool {
	if len(agentVersion) > 64 {
		return false
	}
	parts := managedRuleAgentVersion.FindStringSubmatch(agentVersion)
	if parts == nil {
		return false
	}
	major, majorErr := strconv.Atoi(parts[1])
	minor, minorErr := strconv.Atoi(parts[2])
	_, patchErr := strconv.Atoi(parts[3])
	return majorErr == nil && minorErr == nil && patchErr == nil && (major > 0 || minor >= 6)
}

type rulePackage struct {
	Profile       string         `json:"profile"`
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	PublishedAt   string         `json:"published_at"`
	Categories    []string       `json:"categories"`
	Compatibility map[string]any `json:"compatibility,omitempty"`
	Rules         []model.Rule   `json:"rules,omitempty"`
}

var packageCache = struct {
	sync.Mutex
	items map[string]struct {
		stamp time.Time
		size  int64
		data  rulePackage
	}
}{items: make(map[string]struct {
	stamp time.Time
	size  int64
	data  rulePackage
})}

func packageDir() string { return strings.TrimSpace(os.Getenv("TY_RULE_PACKAGES_DIR")) }
func loadRulePackage(profile string) (rulePackage, error) {
	if packageNames[profile] == "" || packageDir() == "" {
		return rulePackage{}, errors.New("规则方案尚未部署")
	}
	path := filepath.Join(packageDir(), profile+".json")
	packageCache.Lock()
	defer packageCache.Unlock()
	stat, err := os.Stat(path)
	if err != nil {
		return rulePackage{}, errors.New("该规则方案尚无可用版本")
	}
	if cached, ok := packageCache.items[path]; ok && cached.stamp.Equal(stat.ModTime()) && cached.size == stat.Size() {
		return cached.data, nil
	}
	if stat.Size() > 8<<20 {
		return rulePackage{}, errors.New("规则包过大")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return rulePackage{}, err
	}
	var p rulePackage
	if json.Unmarshal(raw, &p) != nil || p.Profile != profile || len(p.Version) != 64 || len(p.Rules) == 0 || len(p.Rules) > 12000 {
		return p, errors.New("规则包校验失败")
	}
	for _, r := range p.Rules {
		if r.Source != profile || r.SourceType != "provider" || (r.Action != "DIRECT" && r.Action != "PROXY" && r.Action != "BLOCK") {
			return p, errors.New("规则包包含非法策略")
		}
	}
	compiled := rules.New().CompilePolicy(p.Rules)
	if _, err = rules.RenderDaeManaged(model.DaePolicy{Profile: profile, Rules: compiled}); err != nil {
		return p, errors.New("规则无法转换为 dae 配置")
	}
	packageCache.items[path] = struct {
		stamp time.Time
		size  int64
		data  rulePackage
	}{stat.ModTime(), stat.Size(), p}
	return p, nil
}
func rulePackageCatalog() []map[string]any {
	out := []map[string]any{}
	for _, id := range []string{"managed_loyal", "managed_meta", "managed_gfw", "managed_geo"} {
		row := map[string]any{"id": id, "name": packageNames[id], "available": false}
		if p, err := loadRulePackage(id); err == nil {
			row["available"] = true
			row["version"] = p.Version
			row["published_at"] = p.PublishedAt
			row["categories"] = p.Categories
			if p.Compatibility != nil {
				row["name"] = p.Name
				row["compatibility"] = p.Compatibility
			}
		}
		if packageDir() != "" {
			if raw, e := os.ReadFile(filepath.Join(packageDir(), id+".status.json")); e == nil {
				var status map[string]any
				if json.Unmarshal(raw, &status) == nil {
					row["update"] = status
				}
			}
		}
		out = append(out, row)
	}
	return out
}
func (s *Server) customerRulePackage(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		Operation string `json:"operation"`
		Profile   string `json:"profile"`
	}
	if decodeJSON(r, &v) != nil || packageNames[v.Profile] == "" {
		writeError(w, 400, "无效的规则方案")
		return
	}
	if packageDir() == "" {
		writeError(w, 503, "规则服务尚未启用")
		return
	}
	switch v.Operation {
	case "update":
		f, err := os.OpenFile(filepath.Join(packageDir(), v.Profile+".request"), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			writeError(w, 503, "无法提交更新任务")
			return
		}
		f.Close()
		writeJSON(w, 202, map[string]any{"message": "已请求检查上游；任务合并执行，通常在几分钟内完成。"})
	case "select":
		if _, err := loadRulePackage(v.Profile); err != nil {
			writeError(w, 409, err.Error())
			return
		}
		if !supportsManagedRulePackages(d.AgentVersion) {
			writeError(w, 409, "请先升级设备 Agent 至 0.6.0 或更高版本")
			return
		}
		updated, err := s.Store.UpdateDevice(r.Context(), d.ID, "", d.Note, v.Profile)
		if err != nil {
			writeError(w, 503, "保存规则方案失败")
			return
		}
		writeJSON(w, 200, map[string]any{"device": updated.CustomerView(), "message": "方案已保存，等待设备拉取并验证应用。"})
	default:
		writeError(w, 400, "不支持的规则操作")
	}
}
