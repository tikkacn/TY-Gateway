# TY Gateway

TY Gateway 是面向 ARM64 单网口旁路由设备的管理与分流软件。本仓库保存可公开的程序源码，并作为**安装包和升级包的公开下载入口**；它不是设备配置或运维工作目录。

## 当前状态

`v0.8.1` 是给第二台全新 Armbian 设备重试的一键安装 Pilot，修复首启服务无法写入 `/etc/ty-gateway` 的问题。它尚未完成真机验收，不应自动部署到已有设备或用于生产环境。

测试设备联网并能访问 GitHub 时，可用以下命令启动安装：

```bash
curl -fsSL https://github.com/tikkacn/TY-Gateway/releases/download/v0.8.1/bootstrap-oec.sh | sudo bash
```

安装器会校验签名软件包；安装前不会启用 DHCP、局域网 DNS 或 DAE 代理。Armbian 的 apt 源仍需可访问。

验收通过后，仓库会提供：

- 新设备安装脚本，以及可通过 U 盘拷贝的离线安装包；
- 经 TY Gateway 发布公钥验证的 ARM64 软件包；
- GitHub 主源、独立 R2 备用源，下载失败时切换，验签失败时停止；
- 已安装设备的本地更新入口；用户只能升级，管理员可以按设备发起受控更新或回退。

GitHub 和 R2 只负责分发。设备身份、订阅、FRP 凭据、密码与私钥均不会放在公开仓库或发布包里。首次联网注册是否成功取决于管理员预登记、云端服务和设备实际网络；仅凭 MAC 认领适用于受控的小规模试点，不能当作强硬件身份验证。

## 安全边界

`release-public.pem` 是**公开验签公钥**，不是登录密码。正式安装必须同时通过签名、版本/平台、文件大小、SHA-256 和安装包内容检查。Pilot 供指定测试设备验收；stable 必须通过全新设备安装、离线升级、回退及重启恢复验证。不要从 issue、评论或非本仓库链接运行安装脚本，也不要在仓库中提交设备凭据或订阅内容。

公开分发域名拟使用 `https://oec.uutec.net`，仅属于 TY Gateway 独立 R2 桶；Guide 项目的 `soft.uutec.net` 和桶不在本项目范围内。

## 发布约定

GitHub Release 的 `v<版本>` 标签保存不可变签名软件包、引导验签器及版本固定的一键安装脚本。TY Gateway 独立 R2 桶保存同一签名包，并镜像 `bootstrap/<版本>/bootstrap-oec.sh` 与验签器，作为备用下载源。未来的 `release-index` 分支保存 `channels/<channel>/linux-arm64/latest.json` 签名版本入口。新版本发布时，安装脚本、验签器和签名软件包必须都读回校验成功，才推进通道指针。公开仓库不保存签名私钥或 R2 写入凭据。

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
