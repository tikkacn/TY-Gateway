# TY Gateway

TY Gateway 是面向 ARM64 单网口旁路由设备的管理与分流软件。本仓库保存完整的可公开源码，并分发签名安装/升级包；不包含设备配置、订阅凭据或运维工作目录。

## 当前测试版本：v0.8.9 Pilot

本轮补齐 LAN DNS 与 DAE DNS 的动态交接，以及 Linux 6.6 之前透明流量入口的兼容处理。代理开启且 DAE DNS 可用时，局域网 DNS 交给 DAE；关闭或不可用时恢复原直连上游，不重启 DHCP 或清租约。旧内核在 DAE 启动/重载后自动校正透明入口，6.6 及更新内核跳过该校正，不改内核或 DAE 二进制。上一轮 6.1.157 测试机已由用户确认 Windows YouTube 在 DAE 重启后仍可访问；全新首装、整机重启和其他内核仍需新一轮实机验收。详见 [DNS 交接](docs/LAN-DNS-HANDOFF.md) 和 [内核兼容](docs/DAE-KERNEL-COMPATIBILITY.md)。

本轮修复设备 HTTPS 通道、设备本机 DNS 与分类节点本地保存。管理员网页仍使用不带端口的原地址；设备内部使用 8443。已有设备的 stock 地址和凭据地址受控迁移，不重新注册。分类选择经本机 DAE 确认后原子保存，常规云端同步保留选择，管理员明确重置才清除本地覆盖。详见 [运行与本地保存说明](docs/LOCAL-PREFERENCES.md)。保留此前管理地址切换、测速、配置备份和升级功能。完成状态见 [功能清单](docs/FEATURES.md)。Pilot 是实机测试版，不是商业稳定版。

上一轮用户确认自动注册和公网 FRP SSH 握手达到测试要求。两台旧测试设备的云端身份、SN、MAC 预登记及 FRP 映射已按用户要求清空；新一轮需重新登记设备真实 MAC，再使用全新 Armbian 测试。设备编号从 1、SSH 映射端口从 22000 重新分配。

## GitHub 一键安装

先在管理员后台预登记设备的实际有线 MAC，可同时绑定规则方案和订阅。不要使用刷机镜像里重复的 MAC。首次安装时保留主路由 DHCP，让设备先正常获取网络；安装器不会自动接管 DHCP。

在支持的 ARM64 Armbian 上以 root 或 sudo 执行：

```bash
curl -fL --retry 3 https://github.com/tikkacn/TY-Gateway/releases/download/v0.8.9/bootstrap-oec.sh -o /tmp/ty-gateway-bootstrap-v0.8.9.sh && sudo bash /tmp/ty-gateway-bootstrap-v0.8.9.sh
```

安装器自动安装运行依赖、固定版本的官方 DAE、设备程序和服务。联网后 Agent 自动认领预登记 MAC、保存专属身份、获取配置并建立 FRP；无需逐台激活文件或在公开脚本里写入 FRP 密码。FRPS 与 FRPC 共用控制端口 **7001**，设备 SSH 映射池为 **22000–22999**。

核心管理服务设为开机启动。新装的代理、DHCP 和局域网 DNS 默认关闭，由用户明确启用。DAE 转发预检与 NetworkManager 接口重连处理包含在安装包中；代理开关跨重启保持用户选择。完整首装后的真实流量及重启状态仍需实机确认。

支持范围是带 systemd、NetworkManager、apt 的 Debian/Ubuntu ARM64 Armbian，并满足 DAE 的 BTF/eBPF 内核要求。安装器不升级 Linux/内核、不改启动链、不自动更换 MAC。不支持的环境会报错，不承诺任意 ARM 板型兼容。首装中断可重跑补齐，已有身份和配置保留；非本项目管理的 DAE 不会被强行覆盖。

## 更新、配置与权限

已安装设备不要重跑首装 bootstrap。此次 Pilot 修复可在旧地址 SSH 执行签名更新器：

```bash
sudo /usr/local/libexec/ty-gateway-update apply-online --channel pilot --expect-version 0.8.9
```

更新保留设备注册、网络及用户配置，不会主动切换管理 IP。也可在“更新与备份”选择测试版，上传同版 `release.json` 和软件包；用户页面的在线按钮只检查稳定版。

本地测速位于“代理与规则 → 网站分流”，支持预设/自定义地址，逐节点显示真实 HTTP 延迟（不是带宽）；没有结果不记零。需 dae 已应用开启状态，测速不会自动开代理。短时诊断结束后恢复原日志级别，短时系统日志按系统策略保留。详见 [测速说明](docs/NODE-LATENCY.md)。

- 本地“更新与备份”提供在线升级及签名离线包上传：`release.json` 与 `ty-gateway-oec-overlay.tar.gz`。用户只能升级；管理员可发起升级及受控回退。
- 导出/导入用户设置不包含设备身份、订阅秘密或 FRP 凭据。导入先校验，不替换强制远程管理信息。
- 重置用户设置会关闭代理、清除用户分流偏好和自定义规则；保留注册身份、管理员基础方案、网络入口及本地密码。这不是擦盘或完整 Linux 恢复出厂。
- 正常客户设置优先使用；管理员仅在用户求助时明确重置，不在常规同步时主动覆盖用户规则。救援/内网直连保护不向客户开放修改。
- 正常升级保留设备注册。彻底重刷且删除本地凭据后，已认领 MAC 不能凭新的随机密钥自动接管，需管理员重置认领。
- 管理员“设备中心 → 查看详情 → 设备反激活”可撤销旧身份，让 MAC 恢复待激活并释放 FRP 登记。与禁用、重置分流分开，不擦除本机系统，不重排其他编号；详见 [反激活说明](docs/DEVICE-DEACTIVATION.md)。该云端功能与 v0.8.6 及后续设备包兼容。

本地安装资产模式为 `bootstrap-oec.sh --package-dir <目录>`；首装系统依赖仍需 apt 网络源，不能称为完全离线首装。已安装设备的签名离线升级不依赖 GitHub 网络。

## 分发与安全边界

Pilot 只使用 GitHub，R2 主备分发推迟至稳定版准备阶段。本轮不修改 Guide 的桶或 `soft.uutec.net`，也不上传 TY Gateway R2。

设备身份、订阅地址、FRP 凭据、本地密码及发布私钥不进入源码或公开包。公开的 `keys/ty-release-public.pem` 是验签公钥。软件包校验签名、平台、版本、大小、SHA-256 和归档内容；校验失败停止安装。MAC 认领是经用户选择的小规模准入方案，MAC 可伪造，不能视为强硬件认证。

FRP 使用设备级 OIDC 凭据及端口授权插件，不把公用 FRP Token 烧进安装器。详见 [FRP 部署说明](docs/FRP-AUTH-DEPLOYMENT.md)。

## 开发与接手

`cmd/`、`internal/` 保存云端与设备源码；`firmware/oec/` 保存受控设备文件；`scripts/` 保存构建/安装/更新工具；`migrations/`、`tests/` 保存迁移与针对性测试。Go 构建需要兼容 `go.mod` 的工具链，脚本另需 Python 3。

接手请先看 [开发交接](docs/AI-HANDOFF.md)、[功能清单](docs/FEATURES.md) 和 [实机验收](docs/OEC-PILOT-ACCEPTANCE.md)。构建模板不是直接安装入口；bootstrap 必须从同版本已签名软件包生成。旧阶段测试包保留，只有用户明确要求时才删除。

仓库尚未选择开源许可证；公开可见不代表已授权第三方复制或再分发。
