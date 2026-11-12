# RT-AC68U / Linux 2.6.36 的 wireguard-go

现已补齐一键部署：运行根目录 `deploy.ps1`，默认连接 `admin@192.168.1.1`，将 `conf.txt` 中的 IPv4 `AllowedIPs` 同步用于 WireGuard Peer、路由和局域网双向转发规则；忽略 DNS 字段，保留现有路由器 DNS。详见 [部署说明](DEPLOY.md)。部署前先将 `conf.txt` 替换为真实配置，并在路由器网页启用 LAN SSH。

校园网 SRun 登录可另装 [校园网自动登录插件](campus/README.md)，在路由器管理员页面设置账号和检查间隔。插件默认关闭，配置与证书保存在本地。

文档、配置模板和测试中的地址均为通用示例，不代表任何实际部署。使用其他 LAN 地址时通过 `-RouterAddress` 指定；安装和启动脚本从路由器 NVRAM 读取实际 LAN 地址。

已在本机交叉编译，产物：`dist/wireguard-go`。这是 WireGuard 用户态守护进程；无须内核 WireGuard 模块，也不依赖 Entware/opkg。

目标环境：ASUS RT-AC68U，ARMv7 little endian，Linux 2.6.36.4brcmarm。编译配置为 Go 1.23.12、`GOOS=linux GOARCH=arm GOARM=7,softfloat CGO_ENABLED=0`，静态链接并去除调试符号。软浮点避免启动时依赖 VFP 配置，ARMv7 则避免旧 ARMv5 运行时对较新内核原子操作辅助函数的依赖。

## 上传和启动检查

先在路由器创建目录：

```sh
mkdir -p /jffs/wireguard
```

在本机 PowerShell 上传，将地址替换成实际路由器 LAN 地址。如果 SSH 端口不是 22，再添加 `-P 端口`。`-O` 使用旧式 SCP，适配未提供 SFTP 的路由器。

```powershell
scp -O .\dist\wireguard-go admin@192.168.1.1:/jffs/wireguard/wireguard-go
```

在路由器 SSH 中执行：

```sh
chmod 755 /jffs/wireguard/wireguard-go
modprobe tun
ls -l /dev/net/tun
/jffs/wireguard/wireguard-go --version
mkdir -p /var/run/wireguard
GOMAXPROCS=2 GOMEMLIMIT=64MiB LOG_LEVEL=verbose /jffs/wireguard/wireguard-go -f wg0
```

正常情况下会出现 `Device started`、`UAPI listener started` 等日志。这个命令在前台运行，按 Ctrl+C 停止。可在另一个 SSH 会话检查：

```sh
ls -l /var/run/wireguard/wg0.sock
ip link show wg0
```

`GOMEMLIMIT=64MiB` 是 Go GC 的软限制，不是进程总内存硬上限。按需调整。确认正常后可使用守护进程模式：

```sh
GOMAXPROCS=2 GOMEMLIMIT=64MiB /jffs/wireguard/wireguard-go wg0
```

手动运行的实例不会自动开机启动。使用一键部署脚本时会安装启动、停止和防火墙恢复钩子，每次开机自动加载 TUN 并恢复配置。本机尚未连接或修改路由器。

## 还需要配置工具

你贴出的环境中没有 `wg`。本工程现在提供配套 `dist/wgctl`，通过 `/var/run/wireguard/wg0.sock` 配置密钥和 Peer；一键部署脚本会自动安装它并设置接口、指定路由和转发规则。它是为此次 IPv4 远端局域网访问实现的 UAPI 客户端，不是完整的官方 `wg` / `wg-quick`。单独启动 `wireguard-go` 仍不会自行读取配置。

没有 Peer 配置时，仅创建接口和 socket 不代表隧道已建立。一键部署会读取你提供的真实配置，自动配置隧道，并且仅为指定远端网段添加路由。

## 源码与兼容补丁

- 官方镜像：https://github.com/WireGuard/wireguard-go
- 上游提交：`b3bc704ef0ee21a36298601a9e1e5ff90377ac52`
- 本地版本标识：`0.0.20250522-b3bc704-rtac68u`
- 源码位于 `source/`；`patches/rtac68u.patch` 包含全部本地修改，可应用到上述提交。
- `rtac68u` 编译标签关闭 UDP `sendmmsg/recvmmsg` 批量路径，改用标准 `sendmsg/recvmsg`。Linux 2.6.36 没有 Linux 3.0 引入的 `sendmmsg`。
- 关闭 UDP GSO/GRO 探测及 TUN `IFF_VNET_HDR`/卸载，使用单包读写，并降低接收缓冲池的批量大小需求。
- 去除该目标上不适用的“内核已有原生 WireGuard”启动提示。
- 不带 `rtac68u` 标签时保留上游的批量和卸载行为。

Go 1.24 起官方要求 Linux 3.2，因此没有使用本机默认的 Go 1.24.0。Go 的 ARM 文档存在架构级更高内核要求，不能仅据“Go 1.23 支持 2.6.32”就保证此固件可用。本构建针对 ARMv7 避开 ARMv5 的旧内核原子辅助函数问题，但最终仍需在这台 Broadcom 内核上验证。

## 重编译

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -RunTests
```

优先使用工程内 `.toolchains/go1.23.12/go/bin/go.exe`，否则通过已安装的 Go 自动选择/下载 `go1.23.12`。脚本校验依赖、可选运行主机测试、交叉编译、检查 ELF 架构和静态链接，并更新 `dist/SHA256SUMS`。不会修改全局 Go 配置。

## 验证范围

本机通过带兼容标签的 `conn`、`device`、`replay`、`ratelimiter`、`tai64n` 测试，其中新增 UDP 双向收发测试覆盖兼容路径、不同报文长度和向接收端点回包。ARM 产物确认是 ELF32 little endian、EM_ARM，无 PT_INTERP / PT_DYNAMIC，构建元数据确认为 Go 1.23.12、CGO 关闭及 ARMv7 softfloat。

Linux ARM 目标的主程序、`conn`、`tun`、`ipc` 通过 `go vet`；`conn` 测试程序也完成 ARM 交叉编译。扩大 `go vet` 到 `device` 时，上游未修改的 `device/pools_test.go:67` 存在 `t.Errorf` 复制 `atomic.Uint32` 锁值的检查告警，未修改该无关测试代码。

未连接路由器，未在目标 Linux 2.6.36 内核上运行或验证实际 Peer 握手、吞吐。主机测试不能替代目标硬件测试。如启动失败，应保留 `--version` 输出、前台 verbose 日志以及 `cat /proc/cpuinfo` 输出。

官方参考：

- https://go.dev/doc/go1.24
- https://go.dev/wiki/Linux
- https://github.com/WireGuard/wireguard-go
