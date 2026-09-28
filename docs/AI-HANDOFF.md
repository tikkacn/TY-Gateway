# TY Gateway 开发交接（公开版）

状态截至 2026-09-28。本文件只供接手开发，不代表现场功能已全部部署。

## 项目结构

- `cmd/tycloud`、`internal/httpapi`、`internal/store`、`migrations`：管理后台、设备准入、订阅/规则和设备命令。
- `cmd/gateway-agent`：设备认领、配置拉取、DAE 状态与受控软件维护命令。
- `cmd/gateway-local`、`internal/localadmin`：本地页面、网络/DHCP/DNS、代理开关、配置导入导出与离线升级入口。
- `cmd/dae-config-helper`、`internal/rules`：节点和规则编译、DAE 校验及应用。
- `internal/release`、`cmd/ty-release-fetch`、`cmd/ty-release-manifest`：Ed25519 签名清单、双源下载、安全解包与哈希校验。
- `firmware/oec/rootfs`、`scripts/build-oec-*`、`scripts/install-oec-overlay.sh`：不改启动链的 ARM64 overlay。
- `scripts/ty-gateway-update.py`、`scripts/ty-gateway-update-service.py`：设备 root 侧升级、快照和回退。

## 当前边界

第一台测试 OEC 不再上线，旧共用 FRP 通道不需为它预留端口；它日后会重新刷系统并使用通用一键安装包。第二台 Armbian OEC 已完成 MAC 修复与自动注册，但 FRP 实际隧道尚未建立，整套首装、离线升级、回退和重启恢复仍未验收。公开 pilot `v0.8.2` 不包含本开发分支的新修复，`stable` 未发布；**不能用“源码已修改”推断现场已升级**。

MAC 预登记后自动认领、每设备 FRP 凭据及端口、管理员远端更新/回退、用户配置备份/恢复等已经有源码和局部测试。自动 FRP 统一使用 22000–22999，FRPC `serverPort` 与 FRPS `bindPort` 共用控制端口 7001；FRPS 通过 per-device 插件授权，只有 MAC 认领的设备进入 roster。插件在 roster 校验通过后改写 Login 签名，FRPS 使用只保存在服务器的非空 Token，因此漏挂插件会被原生认证拒绝；服务器侧设置见 [FRP 授权部署说明](FRP-AUTH-DEPLOYMENT.md)。若部署服务器时仍有依赖旧共享认证的客户端，替换 7001 监听的授权插件前必须先迁移它们。已在管理后台核对并解除离线 OEC1（TY001/#104）的 22000 端口登记；它的注册记录尚在。OEC2（TY002/#105）仍在线，保留原 22001 登记以便对照测试，但登记不代表隧道连通。用户考虑将两台都重新刷机验收，正式清理注册身份须在新安装与云端链路准备好后分阶段进行。MAC 是可伪造的标识，不是强设备身份；当前流程只定位为受控小规模试点。已注册设备身份和 FRP 真实配置不能由用户备份/恢复出厂流程覆盖。

网络服务与 DAE 代理默认关闭。不要为验证软件安装而自动启动 DHCP、LAN DNS 或代理；特别是 DHCP 接管需要先确认上级路由 DHCP 已关闭。对单口设备，不应把安装成功等同于真实局域网流量可代理。

## 安装与版本规则

公开分发仓库为 `tikkacn/TY-Gateway`。公开 pilot `v0.8.2` 已实机暴露安装与集成问题，未通过验收；当前分支修复没有发布。下一候选由本地签名包生成 GitHub-only bootstrap，测试期间不调用 R2、不上传版本。`prepare-oec-bootstrap.py` 默认不嵌入 R2 URL，仅稳定版可显式启用；R2 发布器和 `oec.uutec.net` 留给稳定版阶段。未来若启用 R2，仍需签名包、清单和引导资产读回成功后才推进通道入口。`release-index` 分支是未来工作。签名私钥、R2 写入凭据、FRP token、订阅 URL 和设备凭据永远不进仓库、Release 或安装包。

设备端下载器固定 Ed25519 公钥并校验通道、平台、版本、包大小、SHA-256 和归档安全性。Pilot 阶段只用 GitHub；未来 stable 若启用 GitHub/R2 双源，网络错误才允许切换，签名、哈希或同版本内容冲突时必须停止更新。不要把镜像 URL 做成客户页面任意输入项。

`scripts/bootstrap-oec.template.sh` 不是直接运行的安装器。签名包准备后，`scripts/prepare-oec-bootstrap.py` 会核对独立 ARM64 验签器与**已签名 overlay 内**的验签器完全相同，并生成固定版本/通道/哈希/公钥的首装脚本及本地测试包。默认 GitHub-only；稳定版才可显式加入 R2 fallback。脚本面向 Debian/Ubuntu 系 Armbian，自动安装 `dnsmasq-base`、`python3-dbus` 等 apt 依赖，安装固定 SHA-256 的 DAE 官方 v2.1.1 ARM64 `.deb`，再手工解出二进制、systemd 单元和 geo 数据，绕过会直接调用 `systemctl restart dae` 的 post-install 步骤。可用 `--package-dir` 从本地包目录读取已签名的 TY Gateway 资产及已校验哈希的 DAE 包；仍需访问 apt 源安装系统依赖。它不替换内核，不启用 DHCP、LAN DNS 或代理。离线升级仍使用本地页面上传同一签名包。发布器调用必须提供 `--bootstrap-script <prepare 输出目录>/bootstrap-oec.sh`；不要运行 R2 发布器或上传候选包，直到 stable 阶段获批。

第二台设备报告 `aarch64`、Armbian 26.11 / Ubuntu 26.04、NetworkManager 与 Python DBus 已有、`dnsmasq-base` 和 DAE 尚缺，内核 `6.1.157-rk35xx-ophub`，用户报告 BTF 与 BPF 文件系统可用。其 MAC 经 rkdevinfo 改为 `30:A6:12:09:E4:31`，自动注册在移走旧 MAC 的 pending 文件后成功；Agent 后续应用配置，但 node inventory 曾 HTTP 400，DAE 曾缺 `global {}` 且 systemd 因转发参数失败。用户手工修复后 DAE active；完整 eBPF 配置、重启持久性、真实流量均未验证。没有 `frpc` 进程或 FRP Agent 日志；22001 仅为端口登记。Cloud/数据库/FRPS 新自动注册与 per-device FRP 需按 [OEC 分阶段验收方案](OEC-PILOT-ACCEPTANCE.md)先确认服务端配置，不能以源码存在推断端到端已完成。

## 接手顺序

1. 先看 `README.md`、上述组件及相关测试。不要把本地历史 `work/`、`outputs/` 或部署交接文件整目录推送进本仓库。
2. 只在隔离环境构建候选 ARM64 overlay；使用匹配的 Agent、本地管理、DAE helper、FRPC 和 release-fetch 程序。对候选包做内容/凭据审查，并用固定公钥验证签名与包哈希。
3. 在全新设备完成首次安装、MAC 认领、云端配置、独立 FRP 连接、网络服务默认关闭、离线包升级、失败回退、重启恢复及局域网实际链路测试。记录成功与失败，不以页面提示或节点数量替代网络实测。
4. 通过上述门槛后，把**同一签名清单和不可变包**发布到 GitHub 与 TY Gateway 独立 R2；先发 pilot，确认后再考虑 stable。不要改动其他项目的分发桶。

开发者可先运行 `go test ./internal/release ./cmd/ty-release-fetch` 验证签名下载链；扩大测试应针对实际修改，避免用“全套测试通过”掩盖缺失的真机验证。仓库目前没有选择开源许可证，公开可见不等于已授权第三方再分发。
