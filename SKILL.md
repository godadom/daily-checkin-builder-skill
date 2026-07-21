---
name: daily-checkin-builder
description: "为经授权账号分析脱敏的签到 URL、HAR、Copy as cURL、请求头、接口响应或已有脚本，并生成或修复支持 Cookie、Token、CSRF、多账号和安全重试的 Python 3 自动化，部署到 GitHub Actions、青龙或本地。用户已经提供 Node.js 签到项目时可原位修复，但不从零生成 Node.js。普通网页分析、网页总结、爬取、UI 开发、通用 API/CI，以及未授权访问、凭据窃取、安全挑战绕过、批量注册或刷奖励均不使用。"
---

# 每日签到项目构建

把用户有权自动化的正常签到流程转换为可维护、可测试、可部署的 Python 3 项目。只有用户已经提供 Node.js 签到项目时，才在其现有结构和项目原生工具内修复；不要从零生成 Node.js 项目，也不要把 Python 模板伪装成 Node.js 支持。

## 守住授权和安全边界

1. 将用户直接提出的“分析、生成或修复其签到自动化”请求，视为其对账号归属、正常自动化许可和所述取证范围的声明；直接开始分析，不要求复述固定确认话术。只有账号归属或范围互相矛盾、不明，材料疑似来自他人，或请求触及禁止边界时才暂停澄清。
2. 要求用户先把用于分析的 Cookie、Authorization、Token、密码、手机号、邮箱、设备标识和个人数据替换为明显占位符。若运行时确实需要 Cookie，按 [references/cookie-acquisition.md](references/cookie-acquisition.md) 先尝试正常、已证实的程序化会话获取；无法获取时提供详细的人工导出与安全保存说明。若材料意外包含秘密，不要复述、写盘或提交；提醒用户立即轮换。
3. 只复现用户正常访问时浏览器可见的请求、CSRF 获取方式和客户端公开执行的签名逻辑。
4. 遇到 Turnstile、reCAPTCHA、hCaptcha、WAF、设备证明、WebAuthn、短信验证或其他安全挑战时，立即停止自动提交与重试，并按 [references/camofox-human-handoff.md](references/camofox-human-handoff.md) 检查可选的 `$camofox-browser` 能力。可用时读取其当前说明并尝试一次正常导航；挑战仍存在时按当前 noVNC 流程请求用户本人手动完成。能力不可用、人工接管失败或无人值守执行仍会遇到挑战时，标记为 `UNSUPPORTED_SECURITY_CHALLENGE`。不得自动求解、代打码、规避检测或扩大权限。
5. 拒绝未授权访问、凭据窃取、暴力破解、隐蔽爬取、攻击、批量注册、刷奖励和活动规则滥用。不要提供规避、隐匿或提取他人会话的方法。

详细边界、秘密处理和日志规则见 [references/security.md](references/security.md)。

## 阶段 1：收集并检查输入

1. 按 [references/intake.md](references/intake.md) 收集站点入口、签到页、用户请求声明的范围、目标平台、运行时、IANA 时区、执行时间、抖动、多账号、认证方式、脱敏材料和通知需求；不要求用户重复授权声明。
2. 列出缺失信息。对不影响分析的选项使用文档规定的安全默认值；不要编造 URL、字段、认证方式或响应语义。
3. 区分“可离线分析脱敏材料”和“需要访问真实站点”。用户对该站点签到自动化的直接请求覆盖其所述的正常取证范围；不得扩展到其他账号、站点或操作。范围不明或存在冲突时，不发送真实请求、不运行 live test。
4. 根据任务只读取所需参考文件；若要生成完整项目，读取所有与选定部署目标相关的参考文件。

## 阶段 2：重建正常签到流程

1. 在生成项目中先建立 `docs/site-analysis.md`，按 [references/site-analysis.md](references/site-analysis.md) 记录证据、请求序列、状态判据和未验证假设；同时把 `docs/site-contract.json` 从 `template/scaffold` 更新为 `verified/site_specific`。绝不记录真实秘密，证据不足时不得伪造 verified 状态。
2. 按以下顺序选择实现：正式 API；浏览器实际调用的稳定 HTTP API；必要的公开客户端签名；最后才是在不绕过安全挑战前提下的浏览器自动化。
3. 识别登录、签到前查询、签到请求、签到后验证、CSRF、Token 刷新、重定向和动态参数。没有证据的字段保持为明确假设或阻塞项。
4. 不以 HTTP 200 单独判定成功；组合业务状态码、响应字段、签到状态查询或余额/积分变化。
5. 至少映射 `SUCCESS`、`ALREADY_DONE`、`AUTH_EXPIRED`、`ACCESS_DENIED`、`TEMPORARY_ERROR`、`SITE_CHANGED`、`CONFIG_ERROR` 和 `UNSUPPORTED_SECURITY_CHALLENGE`。
6. 检测到安全挑战时执行 CamoFox/noVNC 人工接管流程；人工通过后只恢复经授权的正常取证。不得把人工挑战步骤包装成无人值守签到方案。

## 阶段 3：生成或修复项目

1. 读取 [references/implementation-contract.md](references/implementation-contract.md)。新建项目或处理 Python 项目时，从 `assets/templates/python-checkin/` 复制骨架，再用已验证事实替换显式占位符；用户已提供 Node.js 项目时保留其结构，只移植同一安全、状态和部署契约。不要把真实凭据写入任何文件。
2. 分离配置、认证、HTTP 客户端、业务状态机、日志脱敏、通知和入口；GitHub Actions、青龙与本地运行必须共用同一业务入口。
3. 将已验证、固定且非敏感的站点事实（origin、路径、固定公开请求头、公开字段名）内置在项目的 `src/checkin/site_config.py`，并在 `site-analysis.md` 标明证据；不得要求操作者把这些值设为环境变量。仅从环境变量、GitHub Secrets 或青龙环境变量读取 Cookie、Token、密码等秘密，以及可变的运行参数。支持结构化多账号配置，并给出格式校验和不泄密的错误信息。
4. 设置连接与读取超时。仅对确定安全的请求自动重试；签到 POST 未确认幂等时，先查询状态再决定是否重试。处理 401、403、409、429、5xx 和 `Retry-After`。
5. 默认串行或低并发执行多账号；单个账号失败不得阻止其余账号，但整体失败必须产生非零退出码。
6. 将异常、HTTP 调试信息和用户声明的敏感字段一并脱敏；禁止记录完整请求头。

## 阶段 4：生成部署配置

- 生成 GitHub Actions 时，读取 [references/github-actions.md](references/github-actions.md)，提供手动与定时入口、最小权限、并发锁、超时、缓存、离线测试、Secrets 映射和失败退出。
- 生成青龙配置时，读取 [references/qinglong.md](references/qinglong.md)，提供 Python 3 入口、cron、环境变量、多账号、依赖、通知、手动测试、凭据更新和故障排查说明。
- 仅生成用户选择的平台；若两者都选，保持一份共享业务逻辑。

## 阶段 5：验证

1. 读取 [references/testing.md](references/testing.md)，使用 mock HTTP 和脱敏 fixture 覆盖配置、单/多账号、成功、已签到、认证过期、CSRF、超时、429、5xx、响应漂移、日志脱敏、部分失败和防重复重试。
2. 默认禁止测试访问真实站点。仅在用户明确授权并主动设置 `LIVE_TEST=1` 时运行 live test；不得在 Pull Request 或 fork 工作流中自动启用。
3. 对 Python 项目先运行完整离线测试，再运行：

   ```text
   python <skill-directory>/scripts/validate_generated_project.py <generated-project> --mode generated
   ```

   对用户提供的现有 Node.js 项目，运行其锁文件对应的原生测试、lint、依赖审计和部署配置检查；明确说明仓库内 Python 生成项目验证器不适用，不得用一次导入或启动冒充完整验证。

4. 安装 `requirements-validation.txt` 后解析生成的 GitHub Actions YAML；若环境提供 `actionlint`，同时运行它。确认青龙命令可直接运行，并检查所有失败路径产生非零退出码。
5. 执行安全审查和差异审查：搜索秘密、个人数据、真实站点残留、完整请求头日志、过宽权限、未固定 Action、联网测试和未验证假设。
6. 用 [examples/trigger-routing.md](examples/trigger-routing.md) 的正向、拒绝和不触发样例回归检查 Skill 路由。

## 完成条件

只有同时满足以下条件才交付：

- 授权、输入、证据、假设和禁止边界清楚；
- `docs/site-analysis.md` 与实现一致且不含秘密；
- 认证、业务、配置、日志和入口边界清晰；
- README、`.env.example`、SECURITY、测试及所选部署文档齐全；
- 项目测试、生成项目验证器和 YAML 检查通过；
- GitHub Actions 或青龙至少一种部署路径完整，本地调试入口可用；
- 安全审查与差异审查无未处理的高风险问题。

最终报告列出生成或修改的文件、验证命令及结果、使用的安全默认值、未验证假设、剩余限制和需要用户提供的下一项材料。

## 参考文件导航

- 输入问卷与脱敏：[references/intake.md](references/intake.md)
- Cookie 获取与会话续用：[references/cookie-acquisition.md](references/cookie-acquisition.md)
- 站点流程取证：[references/site-analysis.md](references/site-analysis.md)
- CamoFox 与 noVNC 人工接管：[references/camofox-human-handoff.md](references/camofox-human-handoff.md)
- 项目与状态契约：[references/implementation-contract.md](references/implementation-contract.md)
- GitHub Actions：[references/github-actions.md](references/github-actions.md)
- 青龙面板：[references/qinglong.md](references/qinglong.md)
- 安全边界：[references/security.md](references/security.md)
- 测试策略：[references/testing.md](references/testing.md)

验证 Skill 本身时运行：

```text
python <skill-directory>/scripts/validate_skill.py <skill-directory>
```

