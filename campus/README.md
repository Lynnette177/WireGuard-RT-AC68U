# 校园网自动登录

此插件将校园网 SRun 登录逻辑移植到 Go，可在无 Python 的 ARMv7 Merlin 路由器上运行。管理页面接入路由器现有管理员登录，提供开关、用户名、密码、检查间隔和在线状态。默认关闭，不会在安装时提交登录请求。

## 当前功能

- 在路由器管理页面「Tools / Campus Login」输入用户名和密码，设置 1–1440 分钟检查间隔。
- 只有确认当前 WAN 不在线时才提交一次登录；如果登录响应不确定，只查询状态，不在同一次检查内重复提交。
- 使用提供的 CA 证书和服务器域名验证 HTTPS；固定连接认证服务器 IPv4 地址，并将连接绑定到路由器 WAN 接口。
- 用户名与密码经浏览器 RSA-OAEP 加密后提交，HTTP 和 HTTPS 管理页面均可使用。HTTP 页面本身不能抵御网络中的主动篡改，因此该加密不能提供 HTTPS 的身份验证和完整性保护。解密后的凭据以明文保存在路由器 root 专用的 `/jffs/addons/campus-login/settings.json`（目录权限 700、文件权限 600），不会写入状态页面或程序日志。拥有路由器 root 权限的人仍可读取该文件。
- 路由器重启后恢复页面和后台服务；WAN 重连后触发一次检查。禁用开关后后台不发起认证请求。
- 更新开关或间隔时，用户名、密码留空会保留已保存的账号；更新账号时需同时填写两个字段。

## 安装

需要 Windows PowerShell、OpenSSH 和打包好的 `dist/campusctl`。将认证服务器地址按 `site.example.json` 的结构保存在 `campus/site.json`，并把认证服务器 CA 证书放在 `campus/campus_root_ca.pem`。这两个文件由 `.gitignore` 排除，公开仓库只包含示例。不要把真实用户名或密码填进这些文件。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\campus\deploy-campus.ps1 -RouterAddress 192.168.1.1
```

将 `192.168.1.1` 换成实际路由器管理地址。安装程序会校验包、备份现有启动钩子、在钩子中插入带标记的调用，并保留原有 WireGuard、软件中心及其他脚本。重复安装会保留账号和加密私钥。安装完成后输出的 `/userN.asp` 是页面路径。

在浏览器登录路由器管理界面，再打开「Tools / Campus Login」或输出的页面路径。浏览器需要支持 BigInt 和 `crypto.getRandomValues`；HTTP 和 HTTPS 均可使用。

## 构建与调试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-campus.ps1 -RunTests
```

安装后可通过 SSH 查看不含用户名和密码的状态：

```sh
/jffs/addons/campus-login/manager.sh status
```

`/tmp/campus-login.log` 和 `/tmp/campus-login-manager.log` 只显示通用错误；认证 URL、挑战、密码和账号不写入日志。服务只处理当前 WAN 连接，不执行原脚本中的 macOS 接口选择，也不对任意第三方 IP 进行认证。

如果状态提示认证未完成，请检查 WAN 连接、路由器系统时间、CA、服务器配置和账号状态。不要将 `/jffs/addons/campus-login/settings.json`、原始登录脚本或包含账号的抓包上传到公共仓库。
