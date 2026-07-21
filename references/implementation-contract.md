# 生成项目实现契约

## 保持单一业务入口

默认生成 Python 3 项目，并让本地、GitHub Actions 与青龙调用同一个入口：

    python -m checkin.main

不得为不同部署平台复制签到逻辑。平台文件只负责安装、注入配置、调度和调用入口。

仓库不提供从零生成 Node.js 项目的模板或验证器。只有用户已提供现有 Node.js 签到项目时，才保留其结构、包管理器、锁文件和入口，并把本文的授权、状态、重试、脱敏、测试和部署约束等价应用到该项目；不得声称 Python 验证器覆盖了 Node.js 输出。

## 划分模块职责

默认采用以下结构；小项目可合并文件，但必须保留职责边界：

    generated-checkin/
    ├── src/checkin/
    │   ├── __init__.py
    │   ├── site_config.py
    │   ├── config.py
    │   ├── client.py
    │   ├── auth.py
    │   ├── service.py
    │   ├── models.py
    │   ├── logging_utils.py
    │   ├── notifier.py
    │   └── main.py
    ├── tests/
    │   ├── fixtures/
    │   ├── test_config.py
    │   ├── test_auth.py
    │   ├── test_checkin.py
    │   └── test_redaction.py
    ├── docs/site-analysis.md
    ├── docs/site-contract.json
    ├── .github/workflows/daily-checkin.yml
    ├── .env.example
    ├── .gitignore
    ├── pyproject.toml
    ├── requirements.txt
    ├── README.md
    ├── DEPLOY_GITHUB.md
    ├── DEPLOY_QINGLONG.md
    └── SECURITY.md

执行以下职责约束：

- 让 `config.py` 只读取环境变量、校验类型并构造账号配置；
- 让 `client.py` 负责 HTTP 会话、超时、重试策略和脱敏后的协议错误；
- 让 `auth.py` 负责装载认证、CSRF 和站点正式支持的 Token 刷新；
- 让 `service.py` 负责“查状态—签到—验结果”的业务状态机；
- 让 `models.py` 定义账号、结果、状态枚举和运行摘要；
- 让 `logging_utils.py` 在日志边界统一脱敏；
- 让 `notifier.py` 只接收脱敏摘要，不读取完整 HTTP 请求；
- 让 `main.py` 编排多账号、通知、汇总和退出码。

禁止模块在导入时发起网络请求或读取秘密文件。

## 定义配置接口

通过环境变量传入秘密和运行配置。至少支持：

- 单账号的明确环境变量；
- 多账号的一个结构化 JSON 环境变量；
- 连接与读取超时；
- 最大安全重试次数；
- IANA 时区和可选小范围抖动；
- 通知渠道的可选配置；
- 日志级别，但调试级别仍必须脱敏。

优先使用稳定、站点无关的名称，并只生成实际需要的变量：

| 建议名称 | 用途 |
| --- | --- |
| `CHECKIN_COOKIE` / `CHECKIN_TOKEN` | 单账号认证；按实际认证方式二选一或另行明确定义 |
| `CHECKIN_ACCOUNTS` | 多账号 JSON |
| `CHECKIN_TIMEZONE` | IANA 时区 |
| `CHECKIN_CONNECT_TIMEOUT` / `CHECKIN_READ_TIMEOUT` | HTTP 超时 |
| `CHECKIN_MAX_RETRIES` | 安全重试上限 |
| `CHECKIN_JITTER_MAX_SECONDS` | 可选削峰抖动上限 |
| `CHECKIN_NOTIFY_CONFIG` | 可选结构化通知配置 |
| `LIVE_TEST` | 仅测试使用的显式真实接口开关 |

对多账号 JSON 执行模式、必需字段、类型和重复标识校验。错误信息只指出账号索引或非敏感别名，不回显原始配置。让 `.env.example` 只包含占位符。

## 使用统一状态模型

至少实现以下状态：

| 状态 | 含义 | 是否视为签到成功 |
| --- | --- | --- |
| `SUCCESS` | 本次完成签到 | 是 |
| `ALREADY_DONE` | 当天此前已完成 | 是 |
| `AUTH_EXPIRED` | 凭据失效或需要用户重新认证 | 否 |
| `ACCESS_DENIED` | 账号已认证但无权执行该操作 | 否 |
| `TEMPORARY_ERROR` | 超时、限流或可恢复服务端错误 | 否 |
| `SITE_CHANGED` | 接口或响应结构可能变化 | 否 |
| `CONFIG_ERROR` | 配置缺失或格式错误 | 否 |
| `UNSUPPORTED_SECURITY_CHALLENGE` | 遇到不得绕过的安全挑战 | 否 |
| `INTERNAL_ERROR` | 未分类且已脱敏的实现异常 | 否 |

让每个账号返回结构化 `CheckinResult`，至少包含非敏感账号别名、状态、短消息、是否重试、尝试次数和可选业务摘要。不得把原始响应、请求头或异常对象直接存入结果。

## 映射错误与响应

按证据映射，不得只按 HTTP 状态猜测：

- 把明确的 401 或认证错误映射为 `AUTH_EXPIRED`；
- 对 403 区分认证失效、权限拒绝和安全挑战；
- 把有明确业务证据的权限拒绝映射为 `ACCESS_DENIED`，不得伪装成 CAPTCHA/WAF；
- 仅在业务响应证明重复签到时把 409 或对应业务码映射为 `ALREADY_DONE`；
- 把 429、超时和可恢复 5xx 映射为 `TEMPORARY_ERROR`；
- 把必需字段缺失、内容类型异常或响应模型变化映射为 `SITE_CHANGED`；
- 把环境变量缺失、JSON 无效和字段校验失败映射为 `CONFIG_ERROR`；
- 把验证码、WAF、设备证明等不可自动化挑战映射为 `UNSUPPORTED_SECURITY_CHALLENGE`；
- 把未知内部异常记录为脱敏错误，并返回非零退出码。

站点分析阶段可按 [CamoFox 与 noVNC 人工接管](camofox-human-handoff.md) 请求用户本人手动通过挑战，但生成项目不得包含验证码求解、挑战 Token 提取、打码服务、反检测配置或无人值守挑战绕过逻辑。只有在人工通过后已验证日常签到请求可在目标部署环境中不再触发挑战，才可交付定时执行；否则保持 `UNSUPPORTED_SECURITY_CHALLENGE`。

刷新 Token 时最多执行一次受控刷新，再重放确定安全的请求。刷新失败后返回 `AUTH_EXPIRED`，不得循环刷新。

## 约束 HTTP 可靠性

- 分别设置连接和读取超时；
- 使用诚实、明确且可维护的 User-Agent；
- 仅自动重试无副作用请求或已确认幂等的请求；
- 对非幂等签到 POST，先查询状态，再决定是否重试；
- 尊重 `Retry-After`，设置最大次数、指数退避和上限；
- 若服务端 `Retry-After` 超过安全等待上限，不得提前重试；直接返回临时错误并等待下一次调度；
- 为响应正文设置固定字节上限；超限时停止读取、不得记录正文，并按站点契约变化处理；
- 避免整点调度；只把小范围抖动用于削峰，不用于规避反机器人系统；
- 默认串行执行多账号；确需并发时使用低并发和独立会话；
- 隔离每个账号的会话、Cookie、Token 和异常。

## 统一日志与通知

在日志调用前完成结构化脱敏，并在异常格式化、HTTP 调试和通知正文上再次应用同一脱敏器。不得打印完整请求头、原始配置、响应正文或命令行秘密。

日志至少输出时间、非敏感账号别名、阶段、状态和短消息。让通知只汇总状态与安全业务字段；通知失败不得掩盖签到结果。

具体敏感字段和轮换要求按 [安全规范](security.md) 执行。

## 定义汇总与退出码

所有账号都执行完后再生成 `RunSummary`。按以下约定退出：

| 退出码 | 条件 |
| --- | --- |
| `0` | 所有账号均为 `SUCCESS` 或 `ALREADY_DONE` |
| `2` | 存在 `CONFIG_ERROR` |
| `3` | 存在 `AUTH_EXPIRED` |
| `4` | 存在 `TEMPORARY_ERROR` |
| `5` | 存在 `SITE_CHANGED` |
| `6` | 存在 `UNSUPPORTED_SECURITY_CHALLENGE` |
| `7` | 存在 `ACCESS_DENIED` |
| `70` | 未分类内部错误 |

出现多种失败时按“权限拒绝、安全挑战、配置、站点变化、认证、临时错误、内部错误”的明确优先级选择一个非零退出码，并在摘要中保留各状态计数。将选定优先级写入 README 和测试，避免平台间不一致。

## 标记模板与站点实现

让可复用骨架的 `docs/site-contract.json` 使用 `analysis_status: template` 和 `implementation_status: scaffold`。只有完成授权取证、替换基线契约并让实现与 `site-analysis.md` 一致后，才改为 `verified` 与 `site_specific`。模板模式只验证骨架安全；交付项目必须通过生成项目模式，后者应拒绝模板域名、基线标题和 scaffold 占位符残留。测试目录中的脱敏 fixture 和保留域名不属于残留。

将已验证、固定且非敏感的站点事实写入 `src/checkin/site_config.py`：HTTPS origin、状态/签到路径、固定公开请求头和公开字段名。它们必须来自 `site-analysis.md`，而非 GitHub Variables、青龙环境变量或本地 `.env`。环境变量只携带秘密和可变运行参数；实现应拒绝 `CHECKIN_BASE_URL`、`CHECKIN_STATUS_PATH` 与 `CHECKIN_ACTION_PATH` 这类运行时覆盖，避免部署配置悄悄偏离已审计契约。

## 生成必需文档

让 README 覆盖用途、授权、平台、原理、环境变量、本地运行、多账号、状态、常见错误和安全事项。分别生成 GitHub Actions 与青龙部署文档；生成 `SECURITY.md` 说明凭据保护、轮换、脱敏报告和不会绕过的安全机制。

在交付前按 [测试规范](testing.md) 验证状态机、重试、脱敏、退出码和多账号汇总。
