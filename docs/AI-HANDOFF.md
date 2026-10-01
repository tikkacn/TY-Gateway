# TY Gateway 开发交接（公开版）

更新：2026-10-01；本轮 v0.8.9 Pilot。以 [功能清单](FEATURES.md) 区分代码实现与实机验收，不得把历史讨论当作已完成功能。

v0.8.9：LAN DNS 动态交接与 DAE 旧内核入口兼容处理已加入
安装/升级/恢复流程；见 [DNS 交接](LAN-DNS-HANDOFF.md) 和
[内核兼容](DAE-KERNEL-COMPATIBILITY.md)。测试机 6.1.157 + DAE 2.1.1
的接管失败已定位为 SO_REUSEPORT 与 TC bpf_sk_assign 不兼容。启动及重载
一次性自动修正后，用户确认 DAE 重启仍能打开 YouTube；设备身份与配置不变。
6.6 及更新内核不套用该修正。尚未整机重启或对其他内核实机验收；不要把候选
当作全新首装已通过验收，也不要再次改用户网关、清库、重新注册或换内核。

## 源码与发布

本仓库为 `tikkacn/TY-Gateway`。此前 `release/` 忽略规则误排除了 `internal/release/`：已发布二进制含有模块，但克隆源码不完整。本轮修复为根目录忽略，并纳入升级验签、下载、安全解包源码及测试。

Agent 默认版本及 Windows/Linux 设备构建脚本统一为 0.8.9。发布包须由干净提交构建，记录对应提交；不得从旧 `work/oec-dist` 默认目录混用历史二进制。构建 ARM64 Agent、local UI、DAE helper、release-fetch，加固定官方 FRPC；签名私钥只在 Cloud 主机上使用，不下载进开发目录。

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

2026-10-01 最新状态：用户已明确拆下测试 OEC，授权新的从零安装轮次。
已备份后清空旧注册设备、两条预登记及设备级配置/FRP 登记；设备编号从 1
开始，端口池 22000–22999 未改。实际本地/公网设备列表 API 都为 0 台，
FRP roster 为 0，7001/Cloud/授权插件正常；全局订阅和规则库保留。
旧凭据匿名撤销哈希保留以拒绝重放，不得删除安全黑名单。

清理后用户确认已重新录入一条待激活预登记，应保留用于下一轮首装，
不得擅自重复清库。历史测试机 .9 的在线验证不再代表当前在线状态，
也不得继续尝试连接已拆下 OEC。新轮首装使用包含本轮修复的 v0.8.9 包。

后台重置前有 root-only 数据库和 FRP roster 备份，可以人工恢复；备份不上传。旧设备凭据已失效，不保留用于新一轮首装。

上一轮用户认可自动注册和通过 FRP 到 SSH 密码提示的测试结果；这证明隧道握手，不证明 root 登录或所有 DAE 转发/离线更新测试完成。新一轮先验一台，再验第二台，检查编号 1/2、端口 22000/22001 和身份不串机。

## 权限与不变量

用户规则优先；管理员只在用户求助时明确重置基础状态。常规云端同步不应覆盖正常用户偏好。设备身份、强制远程维护及内网/救援直连保护不受客户配置导入和重置影响。

FRP 原生 OIDC + 设备端口授权插件已部署。控制端口 7001，映射池 22000–22999。正常升级保留设备凭据；重刷删除身份后需管理员重置认领，不能用 MAC 新密钥接管既有设备。

管理员设备详情提供反激活：Cloud 事务撤销旧密钥、删除旧设备及设备级配置、保留当前 MAC/基础方案/订阅预绑定。部署必须先应用迁移 008。v0.8.6 Agent 不需要变更；旧 Agent 不会自动重新认领，用户需重刷后首装。反激活不擦除本机设置、不重排编号，FRP 断链需等待名单刷新/心跳，见 [反激活说明](DEVICE-DEACTIVATION.md)。

新装代理/DHCP/LAN DNS 默认关，不为安装测试自动接管主路由；代理开关状态应跨重启保存。安装器不更换 MAC、Linux 内核或启动链。NetworkManager 支持显式 forwarding 时配置为 1，旧版依靠 sysctl 与接口 dispatcher；仍需实机重连/重启验证。

## 本轮只做针对性检查

v0.8.7 已修复 UUID/实际 IPv4 有界核验；当前机器使用 .9 可访问。v0.8.8 针对设备 HTTPS/DNS 及分类节点本地优先：stock 设备通道改为 8443，同步凭据地址的受控单向迁移；helper 生成 LAN-only 和管理域名直连 DNS；Cloud 编译规则添加分类/来源/默认动作，明确重置命令添加幂等 payload。部署必须同时包含新版 Cloud、Agent、helper 和页面，不能只更新页面。

本地偏好及修订号位于 applied-snapshot.json，同普通规则/节点原子保存。普通云端同步叠加客户偏好；明确重置才清除，命令重复不会擦掉后来选择。实机默认选择保存和后续同步保留通过；其他客户自定义规则、设置导入/重置仍需云端。见 [本地保存边界](LOCAL-PREFERENCES.md)。只做必要针对性检查，不重刷、不重置设备、不变更 R2。

用户取消过“自动从 DHCP 池排除自身地址”方案，不要重新加入。OEC 固定 IP 要置于池外；修改地址时保留主路由 DHCP，确认后再单独切换 DHCP/DNS。检查软件包、公钥、验签器、签名和 bootstrap 一致；避免扩大测试浪费时间。

先读 [实机验收](OEC-PILOT-ACCEPTANCE.md)。每次失败保留现场并定位对应模块，不宣称源码通过等于实机通过。测速颜色/自定义 URL 已实现，见 [测速说明](NODE-LATENCY.md)；真实出口观察仍未完成。旧阶段包未经用户要求不得删除。
