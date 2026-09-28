# TY Gateway 开发交接（公开版）

状态截至 2026-09-29。本文件只供接手开发，不代表 OEC 真机闭环已通过。

## 项目结构

- `cmd/tycloud`、`internal/httpapi`、`internal/store`、`migrations`：管理后台、设备准入、订阅/规则和设备命令。
- `cmd/gateway-agent`：设备认领、配置拉取、DAE 状态与受控软件维护命令。
- `cmd/gateway-local`、`internal/localadmin`：本地页面、网络/DHCP/DNS、代理开关、配置导入导出与离线升级入口。
- `cmd/dae-config-helper`、`internal/rules`：节点和规则编译、DAE 校验及应用。
- `internal/release`、`cmd/ty-release-fetch`、`cmd/ty-release-manifest`：Ed25519 签名清单、双源下载、安全解包与哈希校验。
- `firmware/oec/rootfs`、`scripts/build-oec-*`、`scripts/install-oec-overlay.sh`：不改启动链的 ARM64 overlay。
- `scripts/ty-gateway-update.py`、`scripts/ty-gateway-update-service.py`：设备 root 侧升级、快照和回退。

## 当前边界

第一台测试 OEC 已退役，不再保留 FRP 端口。第二台 Armbian OEC 的 MAC `30:A6:12:09:E4:31` 已在 Cloud 认领，设备 #105；现有设备凭据应保留。公开 `v0.8.2`/`v0.8.3` 不是本轮候选。`v0.8.4` ARM64 overlay 已本地构建、结构审查，并由 Cloud 主机上与仓库固定公钥匹配的私钥签名；本机验签通过。现可发布为测试 pilot，不能代表真机验收通过。Cloud 的 OIDC 服务和 FRPS 0.71.0 授权链已部署，但真实 OEC2 隧道尚未建立；整套一键首装、离线升级、回退和重启恢复仍未验收。

自动 FRP 使用 FRP 原生设备级 OIDC 客户端凭据：Agent 从现有设备密钥派生专用 FRP 凭据，Cloud 只对已 MAC 认领且启用的设备签发短时 JWT；FRPS 以 OIDC 校验 JWT，插件额外限制设备 ID、SSH 代理名和精确端口。Cloud OIDC issuer 为 `https://oec.188811.xyz/api/v1/frp/oidc`，FRPS/FRPC 共用控制端口 7001，映射池为 22000–22999。FRPS 旧配置及 Cloud 旧二进制/环境均有回滚备份。OEC2 当前手工预留了最先空闲端口 22000，授权 roster 中已有 1 条记录，但设备尚未建立真实 FRPC 会话。FRP v0.71.0 的本机真实二进制 loopback 集成测试已通过；这不等同于现场隧道通过。详见 [FRP 授权部署说明](FRP-AUTH-DEPLOYMENT.md) 与 [FRP OEC2 验收记录](FRP-AUTH-OEC2-TEST.md)。MAC 只能作为首次准入查找标识，不能单独证明已认领设备的所有权。已认领 MAC 在磁盘重刷后不能用新的随机密钥自动接管；需要保留原 `/var/lib/ty-gateway/credentials.json`，或经管理员明确重置认领。

网络服务与 DAE 代理默认关闭。不要为验证软件安装而自动启动 DHCP、LAN DNS 或代理；特别是 DHCP 接管需要先确认上级路由 DHCP 已关闭。对单口设备，不应把安装成功等同于真实局域网流量可代理。

## 安装与版本规则

公开分发仓库为 `tikkacn/TY-Gateway`。`v0.8.2`/`v0.8.3` 已出现真实安装问题；`v0.8.4` 是签名后的测试 pilot，待推送源码并发布 GitHub Release 供 OEC2 一键安装验收。Pilot 仅用 GitHub，不调用 R2，也不修改 `soft.uutec.net` 或其他项目分发。签名私钥、R2 写入凭据、FRP roster token、订阅 URL 和设备凭据永远不进仓库、Release 或安装包。

设备端下载器固定 Ed25519 公钥并校验通道、平台、版本、包大小、SHA-256 和归档安全性。Pilot 阶段只用 GitHub；未来 stable 若启用 GitHub/R2 双源，网络错误才允许切换，签名、哈希或同版本内容冲突时必须停止更新。不要把镜像 URL 做成客户页面任意输入项。

`scripts/bootstrap-oec.template.sh` 不是直接运行的安装器。签名包准备后，`scripts/prepare-oec-bootstrap.py` 核对独立 ARM64 验签器与**已签名 overlay 内**的验签器完全一致，再生成固定版本/通道/哈希/公钥的 GitHub-only bootstrap 和本地包目录。Pilot 不含 R2 fallback。脚本面向 Debian/Ubuntu 系 Armbian，自动安装系统依赖和固定 SHA-256 的官方 DAE v2.1.1 ARM64 包；新装默认不启用代理、DHCP 或 LAN DNS。它会保护已有 `agent.env`、设备凭据和用户配置；对无法证明属于中断安装的现有/活动 DAE 会拒绝覆盖。已完成 bootstrap 的设备需使用签名升级流程，而不是把首装脚本当升级器。

OEC2 的 Armbian 基线为 `aarch64`、Ubuntu 26.04、NetworkManager、内核 `6.1.157-rk35xx-ophub`；用户确认 BTF/BPF fs 可用。其 MAC 已改正并成功首次注册，Cloud 设备 #105 当前在线状态为离线；MAC 已认领，设备有本地凭据时不应因测试而删除。此前 DAE 缺 `global {}` 且 systemd forwarding preflight 失败，用户手工修复后 DAE active；重启持久性和 LAN 真实流量未验证。Cloud 初次注册没有分配 FRP 端口，本轮发现后已分配 22000；Cloud roster 当前 1 条、FRPS 监听 OIDC 已运行，但设备 FRPC/SSH 链路还未验证。

## 接手顺序

1. 先看 `README.md`、上述组件及相关测试。不要把本地历史 `work/`、`outputs/` 或部署交接文件整目录推送进本仓库。
2. 本地候选 `v0.8.4` 已用与固定公钥匹配的远端签名密钥签名且验签通过；先推送经审查的源码和 GitHub-only pilot Release，不上传 R2。
3. OEC2 当前已认领 MAC；用保留身份的签名安装/升级路径验证新 Agent 与 FRP，再实测 FRP SSH 通道。若要重新刷盘验证“首次 MAC 认领”，先由管理员明确重新武装该 MAC；不能删除本地密钥后期待已认领 MAC 自行返回同一身份。
4. Pilot 通过 OEC2 验收后再考虑 stable 或 TY Gateway 独立 R2；不要改动其他项目的分发桶。

开发者可先运行 `go test ./internal/release ./cmd/ty-release-fetch` 验证签名下载链；扩大测试应针对实际修改，避免用“全套测试通过”掩盖缺失的真机验证。仓库目前没有选择开源许可证，公开可见不等于已授权第三方再分发。
