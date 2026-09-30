# TY Gateway 开发交接（公开版）

更新：2026-10-01；本轮候选 v0.8.5 Pilot。以 [功能清单](FEATURES.md) 区分代码实现与实机验收，不得把历史讨论当作已完成功能。

## 源码与发布

本仓库为 `tikkacn/TY-Gateway`。此前 `release/` 忽略规则误排除了 `internal/release/`：已发布二进制含有模块，但克隆源码不完整。本轮修复为根目录忽略，并纳入升级验签、下载、安全解包源码及测试。

Agent 默认版本及设备构建脚本统一为 0.8.5。发布包须由干净提交构建，记录对应提交；不得从旧 `work/oec-dist` 默认目录混用历史二进制。构建 ARM64 Agent、local UI、DAE helper、release-fetch，加固定官方 FRPC；签名私钥只在 Cloud 主机上使用，不下载进开发目录。

`scripts/prepare-oec-bootstrap.py` 对比独立验签器与签名包内验签器，生成固定版本 bootstrap。本轮 GitHub-only Pilot；不改 R2、Guide 或 soft.uutec.net。DAE v2.1.1 官方 ARM64 包由设备下载并检查固定 SHA-256，不随 TY Gateway Release 再分发。

## 组件地图

- `cmd/tycloud`、`internal/httpapi`、`internal/store`、`migrations/`：管理员后台、设备准入、订阅和命令。
- `cmd/gateway-agent`：自动认领、策略拉取、FRP 协调、运行状态及受控维护。
- `cmd/gateway-local`、`internal/localadmin`：本地四菜单、设置、代理、密码、配置备份和离线升级。
- `cmd/dae-config-helper`、`internal/rules`：DAE 节点解析、名称过滤、规则编译及校验应用。
- `internal/release`、`cmd/ty-release-fetch`、`cmd/ty-release-manifest`：Ed25519 签名更新链。
- `firmware/oec/rootfs/`、`scripts/install-oec-overlay.sh`：服务、权限、首次初始化、网络与转发预检。
- `scripts/ty-gateway-update*.py`：root 侧更新、快照、恢复。

## 当前后台与测试状态

按用户明确要求，两台旧测试设备、SN、MAC 准入、认领/身份历史、设备命令及 FRP 登记已清空，设备编号重置为 1，FRP 池 22000–22999 已释放。共享订阅源和通用系统/规则设置保留；订阅节点缓存与刷新统计归零。两台设备刷机后由用户重新录入真实 MAC。

后台重置前有 root-only 数据库和 FRP roster 备份，可以人工恢复；备份不上传。旧设备凭据已失效，不保留用于新一轮首装。

上一轮用户认可自动注册和通过 FRP 到 SSH 密码提示的测试结果；这证明隧道握手，不证明 root 登录或所有 DAE 转发/离线更新测试完成。新一轮先验一台，再验第二台，检查编号 1/2、端口 22000/22001 和身份不串机。

## 权限与不变量

用户规则优先；管理员只在用户求助时明确重置基础状态。常规云端同步不应覆盖正常用户偏好。设备身份、强制远程维护及内网/救援直连保护不受客户配置导入和重置影响。

FRP 原生 OIDC + 设备端口授权插件已部署。控制端口 7001，映射池 22000–22999。正常升级保留设备凭据；重刷删除身份后需管理员重置认领，不能用 MAC 新密钥接管既有设备。

新装代理/DHCP/LAN DNS 默认关，不为安装测试自动接管主路由；代理开关状态应跨重启保存。安装器不更换 MAC、Linux 内核或启动链。NetworkManager 支持显式 forwarding 时配置为 1，旧版依靠 sysctl 与接口 dispatcher；仍需实机重连/重启验证。

## 本轮只做针对性检查

验证升级模块测试、版本默认值、后台统计及干净克隆构建；检查软件包、公钥、验签器、签名和 bootstrap 一致。避免扩大测试浪费时间；真实路由和首装由用户配合。

先读 [实机验收](OEC-PILOT-ACCEPTANCE.md)。每次失败保留现场并定位对应模块，不宣称源码通过等于实机通过。测速颜色/自定义测速 URL、当前真实出口观察等未完成项见 FEATURES.md。旧阶段包未经用户要求不得删除。
