# 管理 IPv4 切换：v0.8.7 Pilot

## 已有证据与修复边界

2026-10-01 的 OEC 日志显示，临时连接在 12:04:26.7882 激活成功，12:04:26.9581 即被 helper 主动回退。确认截止是 12:07:23，因此不是用户未登录导致的三分钟超时。回退恢复原 `Wired connection 1`；用户只读检查确认地址回到 `192.168.0.164/24`。

旧 helper 用连接显示名称和一次原始地址字符串核验，随后把所有失败统一报为“地址切换失败”，没有保留失败检查结果。现有日志不足以证明究竟是状态同步、连接核验还是写入事务失败，不将猜测写成已证实根因。

本轮改动：

- 捕获临时克隆的 UUID，激活/确认用 UUID；不用可变显示名称判定生效。
- 明确禁用 nmcli 颜色和输出转义；解析实际 IPv4 地址及前缀。
- 最多等待 12 秒，并受回退截止限制；地址查询前后 UUID 都必须一致。错误 UUID、错误前缀、残留旧 IPv4 不算成功。
- 记录失败阶段、稳定诊断码和 root-only 事务详情；用户 API 只显示阶段及代码，不暴露详情。未知异常不输出任意异常文本或环境变量。
- 仍保留原连接、NetworkManager 独立回退计时、新地址登录确认和中断恢复；不禁用回退来伪造成功。

针对性检查：10 项纯模拟地址核验、9 项 Linux/POSIX 模拟事务（含未确认回退/崩溃恢复）、本地 API 验证及页面脚本语法。未用这些检查操作任何真实网卡；OEC 实际地址切换仍待用户验证。

## 已安装设备升级

在旧管理地址的 SSH 执行：

```bash
sudo /usr/local/libexec/ty-gateway-update apply-online --channel pilot --expect-version 0.8.7
```

更新器验证签名并保留已有配置与身份，不主动修改 IP。首装 bootstrap 不用于升级。也可在本地“更新与备份”上传 v0.8.7 的签名清单和软件包，选择测试版（Pilot）。页面在线更新按钮目前只查稳定版，不会自动获取 Pilot。

## 本轮最小实机验证

1. 保持主路由 DHCP 开启，先关闭并应用 OEC 的 DHCP/局域网 DNS。不要同时让两端提供 DHCP。
2. 管理地址填 `192.168.0.9/24`，上游网关 `192.168.0.1`；确认 `.9` 未被使用，且在计划的 DHCP 池 `.100–.254` 之外。
3. 点击“仅应用管理地址”，使用 `http://192.168.0.9:8088` 在约三分钟内重新登录。
4. 页面显示“管理地址已确认”后，只读检查 `nmcli -g GENERAL.CONNECTION,GENERAL.CON-UUID,IP4.ADDRESS device show eth0` 应显示新连接及 `.9/24`。超过原确认截止仍可访问才算本轮地址测试通过。
5. 地址确认后，才关闭主路由 DHCP、启用 OEC DHCP/DNS 并单独保存应用。无需为本轮再刷系统或测试其他功能。

旧连接如果使用 DHCP，回退必须能从主路由重新拿到地址，不保证 DHCP 关闭后仍回到旧租约 IP。不要在确认新地址前关闭主路由 DHCP。DHCP 池不会自动摘除 OEC 自身地址：用户已取消此方案，继续要求固定地址在池外。

## 若仍失败

恢复旧地址后保留现场，提供以下只读输出；无需重复改地址碰运气：

```bash
sudo journalctl -b -u ty-gateway-network.service --no-pager -n 40
sudo cat /var/lib/ty-gateway-network/transaction.json
nmcli -g GENERAL.CONNECTION,GENERAL.CON-UUID,IP4.ADDRESS device show eth0
```

事务只包含本次网络切换信息；勿改为输出设备凭据或全部环境配置。`failure_stage` 区分准备/激活/地址核验/确认/事务保存；`failure_code` 和详情用于定位具体失败，而不是继续猜测。
