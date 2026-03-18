# network-fingerprint-audit

一键审计 macOS 当前网络出口、DNS、代理、语言环境、浏览器语言信号，以及浏览器侧 WebRTC / Header 暴露情况，方便复用排查“链路一致性”和“浏览器侧暴露”问题。

## 功能

- 检查公网出口 IP、ASN、地理位置、时区
- 检查系统 DNS、Wi‑Fi DNS、TUN/`utun` 路由、127.0.0.1:53/7890 监听
- 检查系统代理、WPAD 自动代理发现
- 检查 `LANG`、`AppleLanguages`、`AppleLocale`
- 检查 Chrome/Chromium 各 profile 的 `Accept-Language`
- 启动临时 headless Chrome/Chromium，检查浏览器实际发出的 `Accept-Language`、`navigator.language(s)`、WebRTC ICE 候选
- 检查常见 Clash Verge / Mihomo 运行态配置快照
- 基于结果自动生成优先级修复建议
- 自动输出中文 Markdown、HTML 可视化报告和 JSON 到 `reports/`

## 用法

```bash
./bin/audit-network
```

默认行为是：生成报告后自动打开最新的 HTML 可视化页。

可选参数：

```bash
./bin/audit-network --skip-network
./bin/audit-network --skip-browser-probe
./bin/audit-network --no-open
./bin/audit-network --output-dir ./reports
./bin/audit-network --browser-path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

## 输出

运行后会生成：

- `reports/audit-YYYYMMDD-HHMMSS.md`
- `reports/audit-YYYYMMDD-HHMMSS.html`
- `reports/audit-YYYYMMDD-HHMMSS.json`

Markdown 适合快速看结论，HTML 适合直接可视化查看，JSON 适合后续接别的自动化。

## 依赖

- macOS 自带：`scutil`、`networksetup`、`route`、`netstat`、`defaults`
- `python3`
- 可选：本机安装的 Chrome / Chromium / Edge，用于浏览器侧探针

## 说明

- 脚本只抓取审计相关信号，避免把代理订阅、token 等敏感配置整段写入报告。
- 如果你主要用浏览器访问目标服务，重点看 Browser Languages、Public Egress、DNS、Proxy Setup。
- 如果你主要用 CLI / IDE 插件，重点看 `LANG`、系统时区、代理链路、出口 ASN。
- 浏览器侧探针通过本地临时页面复现网页检测站常用的思路：直接在浏览器里调用 `RTCPeerConnection` 和 `fetch`，所以它可以看到 WebRTC ICE 候选和浏览器真正发出的语言头。
- 浏览器侧探针使用临时 headless profile，适合排查链路和暴露面，不等同于完整模拟你日常浏览器的全部反爬指纹。
