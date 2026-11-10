# 一键部署到 RT-AC68U

部署入口：[deploy.ps1](deploy.ps1)。默认目标为 `ssh admin@192.168.1.1`，端口 22。

本页中的地址是示例。实际地址不同时，使用 `-RouterAddress`，例如 `powershell -File .\deploy.ps1 -RouterAddress 192.168.100.1`。安装和启动脚本会从路由器读取真实 LAN 地址，不依赖文档示例。

## 你的部署策略

- 按 `conf.txt` 的 IPv4 `AllowedIPs` 配置 WireGuard、路由及转发规则，不再硬编码为 `192.168.20.0/24`。
- `conf.txt` 的 `DNS` 字段明确忽略，不修改路由器 DNS、DHCP、dnsmasq 或默认网关。
- 例如 `AllowedIPs = 192.168.20.0/24, 10.30.0.1/32, 10.20.0.0/24` 会使三个网段全部生效，包括来源为 `10.20.0.x` 的其他 VPN 客户端。默认路由和包含本地管理地址/与本地 LAN 冲突的网段会报错，不会接管本地网络或默认网关。
- `Address` 的 IP 用作隧道地址，以 `/32` 添加，避免生成额外的整个隧道网段路由；MTU 使用配置中的 1300。
- 本地 LAN 设备通过 NAT 访问远端 LAN。远端设备看到的源地址为 WireGuard 隧道地址，例如 `10.20.0.3`，不需要为本地 `192.168.1.0/24` 另加回程路由。
- 允许本地 LAN 与配置中的远端 LAN、VPN 客户端网段双向主动连接；从隧道进入的新连接只放行到本地 LAN 网段。路由器自身管理服务仍未开放给远端。
- 远端 Peer 仍须允许你的隧道地址，且远端路由器须允许 WireGuard 到其 LAN 的转发；本地脚本无法代替远端配置。

双向主动访问还要求：**远端 WireGuard 节点上，对应这台 AC68U 的 Peer，在原 AllowedIPs 中加入 `192.168.1.0/24`**，并配置该网段经过 WireGuard 的系统路由。不要把这个本地 LAN 网段加到本机 `conf.txt` 的远端 AllowedIPs；本机应配置远端来源/目的网段。如果远端网关 `192.168.20.1` 不是 WireGuard 节点，还需在该网关添加指向实际 WireGuard 节点的 `192.168.1.0/24` 静态路由。远端主机及本地主机自身的防火墙也需要允许所访问服务。

其他网络的 VPN 客户端访问本地 LAN，还要在该客户端的服务器 Peer 中包含 `192.168.1.0/24`，并保证其系统路由指向 VPN。WireGuard 不会把你修改的 AC68U 配置自动推送给其他客户端。中间服务器必须开启 IP 转发，并允许 VPN Peer 之间的转发（通常为同一 WireGuard 接口进、同一接口出的流量）。服务器上 AC68U 的 Peer 应归属 AC68U 的隧道 `/32` 地址和本地 `192.168.1.0/24`，其他客户端的隧道 `/32` 应归属它们各自的 Peer，不能把整个客户端地址池错误归给 AC68U。

本地发起连接的 NAT 保持启用以兼容原有远端配置；它不能代替远端主动连接所需的上述路由。`ip_forward=1` 只是启用内核转发，仍需通过 `WG68_FWD` 的防火墙规则。仅查看 `FORWARD` 主链不能看到自定义链内的最终放行/丢弃规则，应运行 `iptables -L WG68_FWD -n -v`。

## 运行

1. 首次克隆仓库后先运行 `Copy-Item .\conf.example.txt .\conf.txt`，再把 `conf.txt` 中的占位符替换为真实配置。已有真实 `conf.txt` 时直接使用，不要用示例覆盖。使用标准 `[Interface]` / `[Peer]` 格式，不需要修改文件名。真实配置和密钥文件已加入 `.gitignore`。
2. 在路由器网页启用 **LAN SSH**，端口保持 22；不需要启用 WAN SSH，也不需要安装 Entware。
3. 打开本机 PowerShell 执行：

```powershell
cd .\WireGuard-RT-AC68U
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1
```

初次连接可能提示确认 SSH 主机指纹；正常输入路由器 admin 密码。默认不保存密码，上传和安装可能分别询问密码。脚本保留 SSH 主机密钥检查。

只验证真实配置、文件完整性，不连接路由器：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 -ValidateOnly
```

使用其他配置文件、SSH 端口或 SSH 私钥：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy.ps1 -ConfigPath C:\private\wg.conf -SshPort 2222 -IdentityFile "$env:USERPROFILE\.ssh\id_ed25519"
```

当前脱敏配置会在本地校验阶段失败，这是预期行为，不会尝试连接路由器。脚本不需要联网下载依赖，不需要在路由器安装编译环境。

## 脚本具体执行什么

1. 在本机检查配置、密钥格式、Endpoint 格式和文件 SHA256；不解析远端主机名、不输出密钥。
2. 在 Windows 创建仅当前用户和 SYSTEM 可访问的临时目录，打包真实配置、ARM 程序及路由器脚本；原始 `conf.txt` 不修改。
3. 通过 SSH 创建权限 700 的路由器临时目录，再通过兼容旧 SCP 协议上传压缩包。
4. 直接使用已确认具备 root 权限的 admin 会话；检查路由器 ARMv7、TUN、必要命令、JFFS 空间、配置和本地网段冲突。文件内容由配套工具校验 SHA256，不依赖固件提供 `id`、`nohup`、`ip` 或 `sha256sum`。

   工具可用性通过 `iptables -V` 等只读操作实际验证，不再使用旧固件可能误报的 `command -v`。若执行失败，会保留原始错误信息。
5. 备份旧部署及钩子到 `/jffs/wireguard/backups/时间戳/`。文件安装到 `/jffs/wireguard/`，真实配置权限 600，目录权限 700。
6. 安装 `services-start`、`services-stop`、`firewall-start`、`nat-start`、`wan-start` 钩子，开启梅林 `jffs2_scripts=1`。开机自动启动，WAN 接通/重连后重新建立配置并解析 Endpoint，防火墙重载后恢复专用规则。现有钩子原样保存在对应 `.wireguard-original` 文件中，新包装脚本先调用原脚本，再执行 WireGuard 操作（停止钩子顺序相反）。原脚本内的 `exit` 不会跳过 WireGuard 操作。
7. 立即加载 TUN、启动 `wireguard-go`、通过 UAPI 配置 Peer，并由 `wgctl` 直接通过 Linux rtnetlink 设置地址、MTU 和指定路由（无须 iproute2），再设置专用 iptables 链。SSH 断开后守护进程继续运行；停止守护进程时，内核随非持久 TUN 文件关闭自动删除接口及其路由。
8. 启动失败时清理本次接口和规则，恢复旧文件与钩子，原服务运行时尝试恢复启动。错误清理在远程 shell 仍可执行的范围内完成；断电或网络中断无法保证自动恢复。

此处配套工具是本工程的 **`wgctl`**，通过 WireGuard 官方 UAPI 协议配置 `wireguard-go`；它不是官方完整 `wg`/`wg-quick`，不需要 Bash、opkg 或 C 库。当前支持 IPv4 分流配置及多个 AllowedIPs；不执行配置里的任意 Shell 钩子。未知字段、IPv6、默认路由、同一前缀分配给多个 Peer 会在校验阶段明确报错。

内置内存设置为 `GOMAXPROCS=2 GOMEMLIMIT=64MiB`；后者是 Go GC 软限制，不是进程内存硬上限。

## 状态、停止及取消自启

查看状态，不输出私钥或预共享密钥：

```powershell
ssh admin@192.168.1.1 /jffs/wireguard/service.sh status
```

`last_handshake_time_sec` 为非零表示已有握手记录，0 表示尚未握手。启动成功仅表示配置、进程及本地网络设置完成，不能保证远端在线。可以从本地电脑测试访问 `192.168.20.1` 的管理页面或其他远端主机。

临时停止 / 手动重启：

```powershell
ssh admin@192.168.1.1 /jffs/wireguard/service.sh stop
ssh admin@192.168.1.1 /jffs/wireguard/service.sh restart
```

停止并取消本工程的开机、防火墙钩子，恢复原脚本：

```powershell
ssh admin@192.168.1.1 sh /jffs/wireguard/uninstall.sh
```

取消自启会保留 `/jffs/wireguard/` 中的配置和备份，避免丢失密钥；也保留梅林全局 JFFS 脚本开关，避免禁用其他用户脚本。再次运行部署脚本可重新安装。重复部署会停止本工程旧实例、更新配置，并继续保留第一次部署前的原钩子。备份不会自动删除，JFFS 剩余空间少于约 12 MB 时拒绝安装。

如果先前手动启动了另一个 `wireguard-go wg0`，脚本会拒绝接管它。请先在其前台会话按 Ctrl+C 停止，再部署。

日志位于 `/tmp/wireguard-rtac68u/daemon.log` 和 `/tmp/wireguard-rtac68u-hooks.log`，重启后重建。不要将私钥、完整配置或原始 UAPI `get` 响应粘贴到日志中。

## 离线验证范围

已运行：配置校验/管理地址保护/只保留远端网段/DNS 忽略/UAPI 协议/密钥输出过滤/包完整性测试；模拟固件环境下的重复安装、原脚本恢复、失败升级回滚、防火墙规则、服务启停，以及 PowerShell 离线验证。Shell 通过 POSIX 语法检查，PowerShell 通过解析检查。ARM 程序通过静态 ELF 格式检查。

没有连接 `192.168.1.1`，没有修改路由器，尚未在目标硬件上验证部署、重启和握手。

重编译配套工具：`powershell -ExecutionPolicy Bypass -File .\scripts\build-wgctl.ps1 -RunTests`。开发测试还需要本机 Go 1.23.12、Python 和 Git for Windows 的 sh；日常部署只需要 Windows PowerShell 和 OpenSSH 客户端。

协议及固件参考：[WireGuard UAPI](https://www.wireguard.com/xplatform/)、[梅林 User scripts](https://github.com/RMerl/asuswrt-merlin.ng/wiki/User-scripts)。
