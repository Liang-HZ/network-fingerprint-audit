# network-fingerprint-audit

一键审计 macOS 当前网络出口、DNS、代理、语言环境和浏览器语言信号，方便复用排查“链路一致性”和“地域/语言暴露”问题。

## 功能

- 检查公网出口 IP、ASN、地理位置、时区
- 检查系统 DNS、Wi‑Fi DNS、TUN/`utun` 路由、127.0.0.1:53/7890 监听
- 检查系统代理、WPAD 自动代理发现
- 检查 `LANG`、`AppleLanguages`、`AppleLocale`
- 检查 Chrome/Chromium 各 profile 的 `Accept-Language`
- 检查常见 Clash Verge / Mihomo 运行态配置快照
- 自动输出 Markdown 和 JSON 报告到 `reports/`

## 用法

```bash
./bin/audit-network
```

可选参数：

```bash
./bin/audit-network --skip-network
./bin/audit-network --output-dir ./reports
```

## 输出

运行后会生成：

- `reports/audit-YYYYMMDD-HHMMSS.md`
- `reports/audit-YYYYMMDD-HHMMSS.json`

Markdown 适合直接看结论，JSON 适合后续接别的自动化。

## 依赖

- macOS 自带：`scutil`、`networksetup`、`route`、`netstat`、`defaults`
- `python3`

## 说明

- 脚本只抓取审计相关信号，避免把代理订阅、token 等敏感配置整段写入报告。
- 如果你主要用浏览器访问目标服务，重点看 Browser Languages、Public Egress、DNS、Proxy Setup。
- 如果你主要用 CLI / IDE 插件，重点看 `LANG`、系统时区、代理链路、出口 ASN。
