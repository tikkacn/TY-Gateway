package localadmin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tygateway/internal/release"
)

const offlineUploadTimeout = 30 * time.Minute
const offlineUpdateSafetyReserve = 256 << 20

var errOfflineUploadTooLarge = errors.New("离线升级包超过允许大小")

// The local web server is unprivileged. Its update authority is limited to
// fixed socket actions and a random upload ID; the root service validates and
// copies the signed package before asking the updater to install it.
func (s *Server) softwareCall(action string) (map[string]any, error) {
	return s.softwareSocketCall(map[string]string{"action": action}, 35*time.Second)
}

func (s *Server) softwareSocketCall(request map[string]string, timeout time.Duration) (map[string]any, error) {
	if s.cfg.UpdateSocket == "" {
		return nil, errors.New("本机软件更新服务尚未启用")
	}
	connection, err := net.DialTimeout("unix", s.cfg.UpdateSocket, 3*time.Second)
	if err != nil {
		return nil, errors.New("本机软件更新服务暂时不可用")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, errors.New("软件更新请求发送失败")
	}
	var response map[string]any
	if err := json.NewDecoder(io.LimitReader(connection, 8192)).Decode(&response); err != nil {
		return nil, errors.New("软件更新服务没有返回有效结果")
	}
	if message, ok := response["error"].(string); ok && message != "" {
		return nil, errors.New(message)
	}
	return response, nil
}

func (s *Server) softwareStatus(w http.ResponseWriter, _ *http.Request) {
	result, err := s.softwareCall("status")
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) softwareCheck(w http.ResponseWriter, r *http.Request) {
	s.softwareMutation(w, r, "check")
}

func (s *Server) softwareApply(w http.ResponseWriter, r *http.Request) {
	s.softwareMutation(w, r, "apply")
}

func (s *Server) softwareOfflineApply(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 2) {
		writeRateLimit(w)
		return
	}
	if r.ContentLength > int64(release.MaxArtifactBytes+release.MaxBundleBytes+(1<<20)) {
		writeJSON(w, http.StatusRequestEntityTooLarge, apiError{Error: errOfflineUploadTooLarge.Error()})
		return
	}
	if r.ContentLength <= 0 {
		writeJSON(w, http.StatusLengthRequired, apiError{Error: "浏览器未提供上传长度，请刷新后重试"})
		return
	}
	free, err := availableBytes(s.cfg.StateDir)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "无法确认设备剩余空间，暂不接收升级包"})
		return
	}
	required := uint64(r.ContentLength)*2 + offlineUpdateSafetyReserve
	if free < required {
		writeJSON(w, http.StatusInsufficientStorage, apiError{Error: "设备剩余空间不足以安全暂存并回滚，请先释放空间"})
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(offlineUploadTimeout))
	_ = controller.SetWriteDeadline(time.Now().Add(offlineUploadTimeout))
	r.Body = http.MaxBytesReader(w, r.Body, int64(release.MaxArtifactBytes+release.MaxBundleBytes+(1<<20)))

	channel, uploadID, uploadDir, err := s.receiveOfflineUpdate(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errOfflineUploadTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, apiError{Error: err.Error()})
		return
	}
	defer os.RemoveAll(uploadDir)

	result, err := s.softwareSocketCall(map[string]string{
		"action":    "apply-local",
		"channel":   channel,
		"upload_id": uploadID,
	}, offlineUploadTimeout)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) receiveOfflineUpdate(r *http.Request) (channel, uploadID, uploadDir string, err error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return "", "", "", errors.New("请选择签名清单与软件包")
	}

	rootInfo, err := os.Lstat(s.cfg.StateDir)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0077 != 0 {
		return "", "", "", errors.New("设备本地暂存目录不安全")
	}
	root := filepath.Join(s.cfg.StateDir, "offline-update")
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", "", "", errors.New("无法创建离线升级暂存目录")
	}
	rootInfo, err = os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0077 != 0 {
		return "", "", "", errors.New("设备本地暂存目录不安全")
	}
	var rawID [16]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return "", "", "", errors.New("无法建立安全的上传会话")
	}
	uploadID = hex.EncodeToString(rawID[:])
	uploadDir = filepath.Join(root, uploadID)
	if err := os.Mkdir(uploadDir, 0700); err != nil {
		return "", "", "", errors.New("无法建立离线升级暂存目录")
	}
	stagedDir := uploadDir
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(stagedDir)
		}
	}()

	seen := map[string]bool{}
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(nextErr, &maxBytesErr) {
				return "", "", "", errOfflineUploadTooLarge
			}
			return "", "", "", errors.New("离线升级表单读取失败")
		}
		name := part.FormName()
		if seen[name] {
			_ = part.Close()
			return "", "", "", errors.New("离线升级表单字段重复")
		}
		seen[name] = true
		switch name {
		case "channel":
			if part.FileName() != "" {
				_ = part.Close()
				return "", "", "", errors.New("升级通道字段无效")
			}
			value, readErr := io.ReadAll(io.LimitReader(part, 17))
			_ = part.Close()
			if readErr != nil || len(value) > 16 {
				return "", "", "", errors.New("升级通道字段无效")
			}
			channel = string(value)
		case "bundle", "artifact":
			if part.FileName() == "" {
				_ = part.Close()
				return "", "", "", errors.New("请选择签名清单与软件包")
			}
			limit := int64(release.MaxBundleBytes)
			filename := "release.json"
			if name == "artifact" {
				limit = release.MaxArtifactBytes
				filename = "ty-gateway-oec-overlay.tar.gz"
			}
			file, openErr := os.OpenFile(filepath.Join(uploadDir, filename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if openErr != nil {
				_ = part.Close()
				return "", "", "", errors.New("无法保存离线升级文件")
			}
			written, copyErr := io.Copy(file, io.LimitReader(part, limit+1))
			_ = part.Close()
			var maxBytesErr *http.MaxBytesError
			if errors.As(copyErr, &maxBytesErr) {
				copyErr = errOfflineUploadTooLarge
			}
			if copyErr == nil && written > limit {
				copyErr = errOfflineUploadTooLarge
			}
			if copyErr == nil && written == 0 {
				copyErr = errors.New("离线升级文件为空")
			}
			if copyErr == nil {
				copyErr = file.Sync()
			}
			closeErr := file.Close()
			if copyErr == nil {
				copyErr = closeErr
			}
			if copyErr != nil {
				if errors.Is(copyErr, errOfflineUploadTooLarge) {
					return "", "", "", errOfflineUploadTooLarge
				}
				return "", "", "", errors.New("离线升级文件上传失败")
			}
		default:
			_ = part.Close()
			return "", "", "", errors.New("离线升级表单包含不支持的字段")
		}
	}
	if channel != "stable" && channel != "pilot" {
		return "", "", "", errors.New("请选择与签名清单一致的升级通道")
	}
	if !seen["bundle"] || !seen["artifact"] || !seen["channel"] {
		return "", "", "", errors.New("请同时选择签名清单、软件包和版本通道")
	}
	complete = true
	return channel, uploadID, uploadDir, nil
}

func (s *Server) softwareMutation(w http.ResponseWriter, r *http.Request, action string) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 5) {
		writeRateLimit(w)
		return
	}
	if r.ContentLength != 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "software update request must be empty"})
		return
	}
	result, err := s.softwareCall(action)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
