# TY Gateway 开发交接（公开版）

状态截至 2026-09-27。本文件只供接手开发，不代表现场功能已全部部署。

## 项目结构

- `cmd/tycloud`、`internal/httpapi`、`internal/store`、`migrations`：管理后台、设备准入、订阅/规则和设备命令。
- `cmd/gateway-agent`：设备认领、配置拉取、DAE 状态与受控软件维护命令。
- `cmd/gateway-local`、`internal/localadmin`：本地页面、网络/DHCP/DNS、代理开关、配置导入导出与离线升级入口。
- `cmd/dae-config-helper`、`internal/rules`：节点和规则编译、DAE 校验及应用。
- `internal/release`、`cmd/ty-release-fetch`、`cmd/ty-release-manifest`：Ed25519 签名清单、双源下载、安全解包与哈希校验。
- `firmware/oec/rootfs`、`scripts/build-oec-*`、`scripts/install-oec-overlay.sh`：不改启动链的 ARM64 overlay。
- `scripts/ty-gateway-update.py`、`scripts/ty-gateway-update-service.py`：设备 root 侧升级、快照和回退。

## 当前边界

第一台测试 OEC 的现场版本仍是已签名的 pilot `0.7.3`。仓库源码更新于该版本之后，**不能用“源码已上传”推断现场已升级**。第二台全新 Armbian OEC 尚未完成从首次安装到注册、FRP、离线升级、回退和重启恢复的整套验收。`stable` 未发布。

MAC 预登记后自动认领、每设备 FRP 凭据及端口、管理员远端更新/回退、用户配置备份/恢复等已经有源码和局部测试，但匹配的 Cloud 数据库迁移、独立 FRPS listener/plugin、实际设备安装仍是上线前提。MAC 是可伪造的标识，不是强设备身份；当前流程只定位为受控小规模试点。已注册设备身份和 FRP 真实配置不能由用户备份/恢复出厂流程覆盖。

网络服务与 DAE 代理默认关闭。不要为验证软件安装而自动启动 DHCP、LAN DNS 或代理；特别是 DHCP 接管需要先确认上级路由 DHCP 已关闭。对单口设备，不应把安装成功等同于真实局域网流量可代理。

## 安装与版本规则

公开分发仓库为 `tikkacn/TY-Gateway`。GitHub Release 的 `v<版本>` 资产和独立 R2 桶应提供相同签名版本；首装需要的 `bootstrap-oec.sh` 与独立 `ty-release-fetch-linux-arm64` 也必须分别存在于 GitHub Release 和 `oec.uutec.net/bootstrap/<版本>/`。R2 发布器在签名包、清单和引导资产读回成功后，最后才推进通道入口。`release-index` 分支未来保存 `channels/<pilot|stable>/linux-arm64/latest.json`。签名私钥、R2 写入凭据、FRP token、订阅 URL 和设备凭据永远不进仓库、Release 或安装包。

设备端下载器固定 Ed25519 公钥并校验通道、平台、版本、包大小、SHA-256 和归档安全性。GitHub/R2 任一端网络不可用时可用另一端；任一端返回无效签名、坏哈希或同版本内容冲突时应停止更新。不要把镜像 URL 做成客户页面任意输入项。

`scripts/bootstrap-oec.template.sh` 不是直接运行的安装器。签名包准备后，`scripts/prepare-oec-bootstrap.py` 会核对独立 ARM64 验签器与**已签名 overlay 内**的验签器完全相同，并生成固定版本/通道/哈希/公钥的在线首装脚本。脚本面向 Debian/Ubuntu 系 Armbian，自动安装 `dnsmasq-base`、`python3-dbus` 等 apt 依赖，从 dae 官方 v2.1.1 发布下载 ARM64 `.deb` 并固定 SHA-256，再手工解出二进制、systemd 单元和 geo 数据，绕过会直接调用 `systemctl restart dae` 的 post-install 步骤。它不替换内核，不启用 DHCP、LAN DNS 或代理。首装脚本依赖 apt 源、GitHub/R2 分发、DAE 官方 GitHub 均可访问；其中 TY Gateway 包可 GitHub/R2 互为主备，官方 DAE 暂时只从上游 GitHub 下载。这是在线一键安装，不是离线首装包。离线升级仍使用本地页面上传同一签名包。发布器调用必须提供 `--bootstrap-script <prepare 输出目录>/bootstrap-oec.sh`，否则会拒绝发布；生成的 bootstrap 及 Release 资产必须先在第二台 OEC 验收，再公开发布。

第二台预检设备报告 `aarch64`、Armbian 26.11 / Ubuntu 26.04、NetworkManager 与 Python DBus 已有、`dnsmasq-base` 和 DAE 尚缺，内核为 `6.1.157-rk35xx-ophub`，用户报告 BTF 与 BPF 文件系统可用。6.1 满足 DAE 5.17 最低版本，但完整 eBPF 内核配置尚未核实；安装脚本按 dae 官方文档逐项读取配置，BTF 与 bpffs 单独不能作为代理可用证明。应注意当前 Cloud / 数据库 / 独立 FRPS listener 的 MAC 自动注册与 per-device FRP 路径仍在源码阶段，不能据此承诺第二台自动注册和救援隧道会成功。

## 接手顺序

1. 先看 `README.md`、上述组件及相关测试。不要把本地历史 `work/`、`outputs/` 或部署交接文件整目录推送进本仓库。
2. 只在隔离环境构建候选 ARM64 overlay；使用匹配的 Agent、本地管理、DAE helper、FRPC 和 release-fetch 程序。对候选包做内容/凭据审查，并用固定公钥验证签名与包哈希。
3. 在全新设备完成首次安装、MAC 认领、云端配置、独立 FRP 连接、网络服务默认关闭、离线包升级、失败回退、重启恢复及局域网实际链路测试。记录成功与失败，不以页面提示或节点数量替代网络实测。
4. 通过上述门槛后，把**同一签名清单和不可变包**发布到 GitHub 与 TY Gateway 独立 R2；先发 pilot，确认后再考虑 stable。不要改动其他项目的分发桶。

开发者可先运行 `go test ./internal/release ./cmd/ty-release-fetch` 验证签名下载链；扩大测试应针对实际修改，避免用“全套测试通过”掩盖缺失的真机验证。仓库目前没有选择开源许可证，公开可见不等于已授权第三方再分发。
