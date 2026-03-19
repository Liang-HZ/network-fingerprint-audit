# macos-network-fingerprint-audit

一个面向 macOS 的本地审计工具，用来检查“网络出口、DNS、代理、语言环境、浏览器语言信号、浏览器侧 WebRTC / Header 暴露”是否彼此一致。

## 关于作者

我是一个充满好奇心的 AI 应用从业者，关注 AI 产品、自动化工作流，以及把复杂系统整理成可实际落地的工具。

- 联系方式：`shineagentic@duck.com`

## 它解决什么问题

很多“环境不一致”问题并不在单一代理节点，而是出在：

- 系统 DNS 和实际出口不一致
- 终端语言、系统语言、浏览器语言彼此打架
- 浏览器 profile 还保留着旧的 `Accept-Language`
- 浏览器侧 WebRTC 额外暴露了本地地址或另一条公网路径
- 系统代理 / 自动代理发现让不同应用走了不同链路

这个项目的目标不是“伪装指纹”，而是把这些信号收集到一份结构化报告里，方便排查、复查和做前后差异对比。

## 功能

- 检查公网出口 IP、ASN、地理位置、时区
- 检查系统 DNS、当前活跃网络服务 DNS、默认路由、`utun` 分流、127.0.0.1:53/7890 监听
- 检查系统代理、自动代理 URL、WPAD 自动代理发现
- 检查 `LANG`、`LC_ALL`、`AppleLanguages`、`AppleLocale`
- 检查 Chrome / Chromium / Microsoft Edge 各 profile 的 `Accept-Language`
- 启动临时 headless Chrome / Chromium / Edge，检查浏览器实际发出的 `Accept-Language`、`navigator.language(s)`、WebRTC ICE 候选
- 额外扫描常见 Clash Verge / Mihomo 运行态配置快照
- 自动生成中文 Markdown、结构化 HTML 和 JSON 报告

## 兼容范围

- 核心检测依赖 macOS 系统代理、DNS、路由、监听端口和浏览器探针，因此对大多数会影响这些信号的代理方案都适用。
- 当前只有 Clash Verge / Mihomo 提供了额外的运行态配置快照和相关启发式判断。
- 如果某个代理软件不写入系统代理、不走常见本地监听端口、或者使用完全不同的配置路径，系统层和浏览器层结果通常仍可见，但不会有该产品的专项诊断信息。

## 可靠性边界

这个项目定位为“审计 / 诊断工具”，不是“结果保证工具”。

### 相对可靠的部分

这些结果来自系统命令或浏览器实测，可信度相对高：

- `scutil --proxy`、`scutil --dns`、`route`、`netstat`、`networksetup`
- `defaults read -g AppleLanguages`、`defaults read -g AppleLocale`
- 本地浏览器 profile 配置文件中的 `Accept-Language`
- headless 浏览器真实发出的请求头和 WebRTC ICE 候选

### 启发式的部分

这些判断是“提示”，不是绝对结论：

- “Datacenter egress detected” 基于 ASN / 主机名关键词
- “China-oriented public resolvers” 基于常见公共 DNS 列表
- “locale signals include Chinese” 基于本地语言字段的组合判断
- 修复建议本质上是经验规则，不代表唯一正确做法

### 已知限制

- 只支持 macOS；其他系统不会给出可信结果
- 浏览器探针使用临时 headless profile，不等于完整复现你的日常浏览器
- 浏览器探针依赖外网可访问；断网或严格拦截时只能拿到部分数据
- 这不是反检测绕过工具，也不能证明某个目标站点一定“不会风控”

## 可靠性收口

当前实现包含几项关键的稳健性处理：

- 不再把 `networksetup` 查询硬编码到 `Wi-Fi`，而是优先跟随默认路由对应的活跃网络服务
- 语言信号判断同时纳入 `LANG`、`LC_ALL`、`AppleLanguages`、`AppleLocale`
- 增加 Microsoft Edge profile 语言扫描
- 增加最小单元测试，覆盖网络服务解析和区域信号判断

## 依赖

- macOS 自带：`scutil`、`networksetup`、`route`、`netstat`、`defaults`
- `python3`
- 可选：Chrome / Chromium / Edge，用于浏览器侧探针

## 快速开始

```bash
git clone https://github.com/Liang-HZ/network-fingerprint-audit.git
cd network-fingerprint-audit
./bin/audit-network
```

默认行为：

- 采集本机信号
- 生成报告到 `reports/`
- 自动打开最新的 HTML 报告

如果你已经有本地仓库副本，直接在仓库根目录运行：

```bash
./bin/audit-network
```

## 常用参数

```bash
./bin/audit-network --skip-network
./bin/audit-network --skip-browser-probe
./bin/audit-network --no-open
./bin/audit-network --output-dir ./reports
./bin/audit-network --browser-path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

## 输出

每次运行会生成：

- `reports/audit-YYYYMMDD-HHMMSS.md`
- `reports/audit-YYYYMMDD-HHMMSS.html`
- `reports/audit-YYYYMMDD-HHMMSS.json`

其中：

- Markdown 适合快速看结论
- HTML 适合按模块浏览和复查
- JSON 适合做前后 diff 或接入别的自动化

## HTML 报告结构

- 左侧固定目录，便于在长报告里跳转
- 顶部概览区，先看高 / 中 / 低风险分布
- `主要发现` 用表格集中展示问题和证据
- `修复建议` 给出按优先级排序的处理方向
- `浏览器与 WebRTC`、`网络与区域信号`、`代理设置`、`代理运行态快照` 分模块展示

这份布局优先服务排障，而不是展示炫技 UI。

## 如何理解结果

- `高风险`：更可能导致“出口和环境看起来不像同一台机器/同一类用户”
- `中风险`：存在明显不一致，但未必单独触发问题
- `低风险`：会增加复杂性或不确定性
- `信息`：主要用于补全上下文，不一定需要处理

比较推荐的用法是：

1. 修改一个变量，例如 DNS、代理或浏览器语言
2. 重新运行审计
3. 对比前后两份 JSON 报告

这样比只看单次结果更有价值。

## 隐私与安全

- 脚本只抓取排障相关字段
- 当前内置的 Clash/Mihomo 配置快照只保留去敏后的关键片段，不会整段写入订阅或 token
- 报告默认不再写入主机名、当前工作目录；家目录绝对路径会被脱敏成 `~`
- 浏览器探针在本地临时目录运行，结束后清理 profile
- 生成的报告保存在本地 `reports/`，不会自动上传
- `reports/` 已被 `.gitignore` 忽略，不建议把生成报告公开发布

## 验证

当前仓库至少应通过：

```bash
python3 -m py_compile network_audit.py
python3 -m unittest discover -s tests -v
python3 network_audit.py --no-open
python3 network_audit.py --skip-network --no-open
python3 network_audit.py --skip-browser-probe --no-open
```

## 不在本项目目标内的内容

- 不承诺“修复后一切站点都通过”
- 不负责伪造完整浏览器指纹
- 不尝试绕过站点风控策略
- 不替代代理、DNS 或浏览器本身的正确配置
