# TY Gateway OEC 部署包

## 当前结论

上一版整盘候选镜像已经废弃：它基于 wxy-oect，没有在普通 OEC 上证明启动链、设备树、分区和网络兼容性，并且实机未能启动联网。不要再次刷写 work/oec-candidate-bundle-20260914/ 或其中的 oec-base.img。

普通 OEC 的正确顺序是：

OEC 专用底包（原样刷入） → 实机验收启动、DHCP、SSH、重启 → TY Gateway overlay（只写入系统文件，不修改 boot、Loader、DTB） → Agent 注册、配置下发、上海 FRP 救援联调。

社区资料显示 OEC/OECT 有多个板版本，Loader 和系统包不能按普通 RK3566 混用。oec-jp 等包只是社区经验，不等于本机已验证；必须先用与板版本匹配的包验证底包本身。

## 现在可以构建的包

先构建 ARM64 程序，再组装 overlay：

    .\scripts\build-oec-agent.ps1 -OutputDirectory work\oec-dist
    .\scripts\build-oec-overlay.ps1 -OutDir work\oec-overlay

或在 Linux/WSL 执行：

    bash scripts/build-oec-agent.sh work/oec-dist
    bash scripts/build-oec-overlay.sh work/oec-overlay

输出是一个不含秘密的目录和压缩包，包含 ARM64 Agent、本地管理 Web 服务、root 限权的 dae 配置辅助器、ARM64 frpc、systemd 单元、首次初始化脚本、安装器、SHA-256 清单和底包兼容性声明。

该包不会包含管理员 Token、设备 secret、恢复私钥、订阅 URL、节点凭据，也不会改写 Loader、内核、DTB、boot 分区或磁盘分区表。默认不内置恢复公钥；因此未专门配置密钥前，不能声称设备密码恢复已启用。

## 在 OEC 上安装叠加包

默认按 IPv4 默认路由自动识别网卡，不再假设接口名一定是 `eth0`；多网卡设备可在 Agent 与本地管理配置中分别显式指定同一 LAN 网卡。

先把 OEC 专用底包原样刷入并确认可以通过 SSH 登录。将 overlay 解压到 OEC 后，以 root 执行：

    cd /path/to/oec-overlay
    chmod +x install-oec-overlay.sh payload/usr/local/bin/ty-gateway-agent payload/usr/local/bin/ty-gateway-local payload/usr/local/bin/frpc payload/usr/local/libexec/ty-gateway-dae-helper payload/usr/local/libexec/ty-gateway-firstboot
    ./install-oec-overlay.sh

安装器会先验证包内 `SHA256SUMS`，再用新 FRPC 检查现有 `/etc/ty-gateway/frpc.toml`（若存在）；校验失败时不会覆盖设备文件。CRLF 格式的校验清单也会逐项校验，不会跳过校验。安装过程中会对将要改写的文件做权限受限的临时备份，若写入或服务更新失败会尝试恢复文件及已触碰服务的原运行状态，并报告回退是否完整。

首次安装时按默认策略启用本地管理、dae 辅助器、firstboot 和 Agent。Agent 会在首次联网时尝试以设备有线 MAC 认领后台预登记的 MAC；后台未登记或网络不可用时会重试，但不会因此启用 DHCP、DNS 或 dae 代理。该 MAC 首次认领存在可被仿冒/抢先认领的风险，因此仅适合受控小范围试点。新流程需要 Cloud 端应用匹配的数据库迁移和程序版本；本地测试通过不代表生产 Cloud 或设备已升级。

每设备自动 FRP 由 Agent 根据 Cloud 认证配置管理为独立子进程，SSH 映射端口为 22000–22999。FRPC `serverPort` 与 FRPS `bindPort` 使用相同控制端口 7001；旧共享认证路径需由 per-device 授权插件替换，切换前确认没有仍依赖旧共享认证的设备，再在现有 7001 监听上部署插件/roster、TLS 与 Cloud 配置。FRPS 必须同时配置仅服务端持有的非空 Token；授权插件只在通过每设备 roster 校验后为 FRPS 改写登录签名，所以漏挂插件会被 FRPS 原生 Token 校验拒绝。安装器仍保留已有设备的旧 FRPC 配置与服务状态，不会擅自停止正在运行的远程救援链路；这不表示新安装需要旧共享凭据。升级时保留现有服务启停与屏蔽状态；现有 `agent.env`、`local.env` 和设备凭据均保留。新建的 `local.env` 仅 root 与 `tylocal` 组可读。服务端操作要求见 [FRP 授权部署说明](../../docs/FRP-AUTH-DEPLOYMENT.md)。

一键安装使用 root 专有的 `/var/lib/ty-gateway-bootstrap/state` 区分“安装中”和“已完成”，并对并发运行加锁。中断后重跑同一受信脚本会再次校验签名与哈希，对固定路径的软件文件补齐或重新写入，保留设备凭据、用户设置和订阅状态；账户创建及服务启用是幂等操作。只有首次安装的续装模式会补启因断电而留下的已存在但未启动的核心服务；普通升级仍保留既有启停状态。已完成的首装重跑不会重复创建实例或重置配置。DAE、DHCP、局域网 DNS 依旧按用户开关控制，不因“管理服务开机自启”而自动开启。旧版中断但尚无 Agent 的设备，只在 DAE 二进制、单元、数据及默认关闭配置均与固定版本一致时允许续装。

首次设置本地管理密码时至少 12 个字符；设备码只作身份标识，不是登录口令。服务默认在 `http://<OEC-LAN-IP>:8088` 提供页面；`feiliu.local` 需要目标镜像的 mDNS 解析经验证后再作为正式入口。普通用户侧不显示订阅 URL、邮箱、管理备注或节点服务器凭据。当前页面可显示设备码与本机 LAN 地址、设置/修改本地密码；恢复挑战端到端需配置并验证与云端匹配的公钥。DHCP、DNS 和 IP/MAC 保留可通过“保存并应用配置”实际执行；端口转发尚未实现。启用 DHCP 前必须关闭主路由 DHCP。

本地管理程序以单独的低权限 `tylocal` 用户运行，密码摘要保存在 `/var/lib/ty-gateway-local`，不与 Agent 的设备凭据目录共享。`TY_LOCAL_INTERFACE` 应与 Agent 绑定的 LAN 接口一致。网页可校验并保存单网口网络预设及最多 256 条 MAC/IP 绑定。保存配置后可明确确认只应用 OEC 自身的固定 IPv4 地址和上游网关；自动检测局域网 ARP 冲突，使用 NetworkManager 临时连接和独立回滚检查点切换，用户须从新地址重新登录确认，180 秒未确认则 NetworkManager 自动恢复。旧 DHCP 连接配置不会被删除；失败时 helper 也会尝试恢复原连接。“仅应用管理地址”不会启用 LAN 服务；DHCP、LAN DNS 与 MAC/IP 固定分配使用独立的“保存并应用配置”，实际操作见 `docs/OEC-LAN-SERVICES.md`。端口转发和 dae 不随这些操作启用。地址须排除在主路由 DHCP 地址池外；随机 MAC 仍可能使终端绑定失效。

本地设备管理页分为“设备与网络”“代理与规则”“密码管理”三个菜单。网络页会读取 OEC 当前 IPv4 ARP 缓存，显示观察到的客户端 IP、MAC 和状态；点击“加入绑定”只加入待保存列表，手工填写仍可用，最终仍需保存并应用配置。休眠设备可能暂时不显示，随机 MAC 会按当前观测值处理。本地页有独立的“科学上网”开关，默认关闭。登录 OEC 本地管理页后开启，会让把 OEC 设为 IPv4 网关的局域网设备按已下发的规则和节点分流；关闭时 Agent 将通过 dae helper 重载直连规则。开启要求已绑定并同步有效订阅，先由 dae 校验配置，失败会回滚。云端临时“全局直连”在有效期内优先于本地开关。该开关不修改 DHCP、DNS 或 OEC 管理地址。

Agent 通过单独的 `typroxy` 组 Unix socket 向本地管理程序提供窄接口，只接受状态查询及布尔开关，不暴露订阅 URL、节点凭据或任意 dae 配置。开关状态以 0600 文件保存在 Agent 私有目录；云端短时不可达时，可用本机最后一次同步的规则启用，连接恢复后 Agent 自动获取最新配置。

快速验证首装及安全重复安装可在 Bash 环境执行：

    TY_OVERLAY_TEST_SCOPE=install-idempotency bash scripts/test-install-oec-overlay.sh

模拟首装中断后补齐服务可单独验证：

    TY_OVERLAY_TEST_SCOPE=interrupted-repair bash scripts/test-install-oec-overlay.sh

完整安装器回归测试：

    bash scripts/test-install-oec-overlay.sh

测试使用临时根目录和模拟的 systemd 命令，不会修改当前电脑的服务或网络；覆盖首装、重复安装、FRPC 启用/运行/停止/屏蔽状态、校验失败及安装回退。它不能替代在 OEC 上的升级与重启验收。

dae 辅助器以 root 运行，但只接受受限 Unix socket 上的订阅配置请求，不执行任意 shell；它将订阅响应暂存为 `/etc/dae/ty-gateway/subscription.raw`（权限 0600），向 dae 添加单独的托管配置 include，先运行 `dae validate` 再 reload。失败时恢复 dae 配置和上一份订阅。URL 和响应正文不会写入 Agent 状态文件或日志。overlay 安装器不会改写 `/boot`、Loader、DTB 或现有网卡配置。手动安装 overlay 前需准备 `dnsmasq-base`、`python3-dbus`、NetworkManager 和官方 dae；新设备应使用生成的 `bootstrap-oec.sh`，它自动安装缺失的 apt 运行依赖、校验并安装固定版本的官方 DAE，再安装签名 overlay。它不会运行 DAE Debian 包的 post-install 脚本，也不会启用 DAE、DHCP 或局域网 DNS。首次安装的 Agent 会按 `TY_AGENT_AUTO_ENROLL` 自动尝试 MAC allowlist 认领；升级保留已有 credentials。通用包不携带上海 FRPS 全局 token、roster token、设备 secret 或激活文件。每设备 FRP 源码使用独立 control listener、端口池、TLS CA 和设备/端口派生凭据；Cloud 开关默认关闭，只有完成独立 FRPS/plugin 部署并配置 `TY_FRP_AUTO_ENABLED=1` 后才可能下发。**本分支的新自动 FRP 部署链路尚未在 Cloud、FRPS 和 OEC2 完成集成验收**；OEC2 现有旧版本/局部服务状态不代表新链路已部署。

绑定 LAN 的 dae 要求接口的 IPv6 forwarding 为 1；`0` 表示该接口未开启 IPv6 转发，不等同于“DAE 已关闭”的完整状态。旧版 NetworkManager 在重新接管网卡时可能将该接口参数重置为 0，即使 `/etc/sysctl.d` 已设置为 1。dae 启动前检查会在支持 `ipv6.forwarding` 的 NetworkManager 上，把**当前托管 LAN 连接的配置**持久设为 `yes`，不重新激活连接；旧版本或设置失败则依靠运行时写入。NetworkManager 网卡上线、重新应用和 DHCP 变化后也会触发检查。用户关闭代理时不会为了改写 sysctl 而启动 DAE；已经写入的连接属性不随代理开关复位。用户开启代理并保存后，Agent 会保存开关状态、启用 dae 开机服务，并在重启时恢复已验证的策略。只处理 dae 托管配置指定的接口，不会更改网卡地址或启动 DHCP/DNS；不要只依赖开机执行一次的 sysctl 设置。

若是新装 overlay，Agent 会在首次联网后自动注册；若是旧包或关闭了自动注册，则仍可在 OEC 本地串口或 SSH 控制台手动执行：

    systemctl start ty-gateway-firstboot.service
    runuser -u tygateway -- /usr/local/bin/ty-gateway-agent --enroll
    systemctl restart ty-gateway-agent.service

注册成功后，在中央后台确认设备编号、设备码、在线状态和配置版本。绑定订阅后请求 dae 同步，设备下次轮询后 dae 会自行解析并回报实际总数。客户网页的逐节点选择仍使用安全元数据清单，可能暂时少于 dae 实际总数；两种数量不会再混为一谈。Agent 只执行白名单命令，不执行云端任意 shell。

## 实机验收门槛

底包原样刷入后，先记录 model、kernel、网卡、地址和路由。必须完成：

1. OEC 能从 eMMC 正常启动；
2. 网线接入后能获得 DHCP 地址；
3. 局域网 SSH 能稳定登录；
4. 重启后仍能重复通过前 3 项。

任何一项失败，问题属于底包、Loader、板版本或网络兼容性，不应通过修改 TY Agent 掩盖。

## 关于轻量化

之前约 3.87GB 是整盘镜像文件大小，不是 Agent 的运行内存需求。最终系统大小由 OEC 专用底包的分区和启动链决定，不能为了变小而重建分区或删除未知分区。部署不装桌面、Docker、面板或编译工具链，也不替换系统内核。DAE 是否可用还取决于内核版本及官方列出的 eBPF 配置；仅有 BTF 与 BPF 文件系统不足以证明 DAE 可代理。待底包原样稳定后，再按 2GB 内存和 8GB eMMC 做日志、缓存配额与 dae 实测。

## 旧整盘构建脚本

build-oec-bundle.ps1/.sh 已加安全门：只有 firmware/oec/target.json 明确标记为 ready-for-oec-validation 时才允许生成整盘包。当前状态为 awaiting-oec-specific-base，因此不会误把未验证底包打成可刷镜像。

## 参考资料

- OEC 官方规格：https://help.onethingcloud.com/be81/OEC1/8127
- OEC/OECT 社区底包与板版本说明：https://blog.dmoe.top/posts/course-OECT-armbian
- OEC JP 社区教程：https://www.17nas.com/onething-cloud-oec-armbian-tutorial
- OEC 底包兼容性研究记录：../../docs/OEC-BASE-RESEARCH-20260915.md
