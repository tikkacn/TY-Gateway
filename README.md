# TY Gateway

TY Gateway 是面向 ARM64 单网口旁路由设备的管理与分流软件。本仓库保存可公开的程序源码，并作为**安装包和升级包的公开下载入口**；它不是设备配置或运维工作目录。

## 当前状态

公开的 `v0.8.2` Pilot 尚未通过真机验收：OEC2 上发现 MAC/pending 身份不匹配、DAE 首配/转发问题，且自动 FRP 隧道未建立。该版本不包含当前开发分支的修正，不要再把它当作成功的一键安装包。候选版本仍在本地开发，未签名、未发布、未部署；待分阶段本地检查通过后再通知用户进行 OEC2 验收。

当前开发分支尚未发布：每设备自动 FRP 的 SSH 映射端口为 22000–22999；FRPC `serverPort` 与 FRPS `bindPort` 使用同一个控制端口 7001，设备凭据由 per-device 授权插件校验。OEC1 不再作为本轮测试设备；OEC2 的 22001 端口登记不等于隧道已连通。自动 FRP 还依赖 Cloud 新配置、FRPS 7001 插件配置及 roster。Pilot 安装器将默认只走 GitHub；R2 上传与备用源仅在稳定版准备阶段启用。代码通过本地测试不表示已部署到 Cloud、FRPS 或设备。

FRPS 还必须持有一个非空且只存于服务器的强 Token，并由 per-device 插件在原生 Token 校验前改写已授权设备的登录签名；这样插件漏配时设备会被 FRPS 拒绝。服务器侧配置要求见 [FRP 授权部署说明](docs/FRP-AUTH-DEPLOYMENT.md)。

测试阶段不要运行旧的 `v0.8.2` 安装命令。按 [OEC 分阶段验收方案](docs/OEC-PILOT-ACCEPTANCE.md)先完成本地包、MAC 准入、规则/订阅、FRP、DAE 与真实转发的门槛，再准备 OEC2 真机测试。

验收通过后，仓库会提供：

- 新设备安装脚本，以及可通过 U 盘拷贝的离线安装包；
- 经 TY Gateway 发布公钥验证的 ARM64 软件包；
- Pilot 从 GitHub 下载；稳定版准备阶段再接入独立 R2 备用源，验签失败时停止；
- 已安装设备的本地更新入口；用户只能升级，管理员可以按设备发起受控更新或回退。

GitHub 和 R2 只负责分发。设备身份、订阅、FRP 凭据、密码与私钥均不会放在公开仓库或发布包里。首次联网注册是否成功取决于管理员预登记、云端服务和设备实际网络；仅凭 MAC 认领适用于受控的小规模试点，不能当作强硬件身份验证。

## 安全边界

`release-public.pem` 是**公开验签公钥**，不是登录密码。正式安装必须同时通过签名、版本/平台、文件大小、SHA-256 和安装包内容检查。Pilot 供指定测试设备验收；stable 必须通过全新设备安装、离线升级、回退及重启恢复验证。不要从 issue、评论或非本仓库链接运行安装脚本，也不要在仓库中提交设备凭据或订阅内容。

公开分发域名 `https://oec.uutec.net` 属于 TY Gateway 独立 R2 桶。本轮 Pilot 不上传 R2、不使用该域名；Guide 项目的 `soft.uutec.net` 和桶不在本项目范围内。

## 发布约定

Pilot 通过验收前不发布候选版本；验收中的 Pilot 使用 GitHub Release 作为唯一在线源。stable 阶段再考虑 TY Gateway 独立 R2 桶、备用源和 `release-index` 通道指针。公开仓库不保存签名私钥或 R2 写入凭据。

Pilot 命令只用于这次第二台设备验收；根据实测结果修正后再决定是否发布 stable。

`scripts/bootstrap-oec.template.sh` 与 `scripts/prepare-oec-bootstrap.py` 是构建阶段源码，不是可直接运行的安装入口。实际安装脚本必须由已签名的软件包生成，并固定版本、验签器哈希和公钥；Pilot 供新设备验收。

当前模板已包含完整的 Armbian 首装流程：安装 `dnsmasq-base`、`python3-dbus` 等运行依赖；从 DAE 官方 GitHub 下载 ARM64 `dae` 2.1.1 并校验固定 SHA-256；安全解出程序、systemd 单元和规则数据，再安装经 TY Gateway 固定公钥验证的设备程序包。它只支持带 systemd、NetworkManager、apt 的 Debian/Ubuntu ARM64 Armbian。安装器不升级系统、不替换内核、不配置网卡地址，并让 DHCP、局域网 DNS 和代理开关保持关闭。DAE 的 eBPF 内核配置检查会引用官方要求；检查未通过时软件可安装，但代理必须保持关闭。测试包还提供 `--package-dir` 本地资产模式，但 apt 系统依赖仍需联网安装。

DAE 二进制由设备在安装时直接从 [daeuniverse/dae 官方发布](https://github.com/daeuniverse/dae/releases/tag/v2.1.1)获取，版本与 SHA-256 固定在安装模板中；我们不把 DAE 二进制重新打包上传到 TY Gateway 的 GitHub 或 R2。

## 源码索引

- `cmd/`、`internal/`：云端、设备 Agent、本地管理页、规则与签名更新逻辑。
- `firmware/oec/`：ARM64 设备 overlay 的受控服务文件与示例配置。
- `scripts/`：构建、安装、签名包准备和回退脚本。这里的构建脚本不会在设备上自动执行。
- `migrations/`、`tests/`：数据库迁移与回归测试。

后续 AI 接手请先读 [开发交接](docs/AI-HANDOFF.md)，尤其注意源码版本与现场测试设备版本并不相同。

源码公开不等于现场已部署，更不等于可商用稳定版。仓库尚未选择开源许可证；在许可证明确前，公开可见不代表允许第三方复制或再分发。
