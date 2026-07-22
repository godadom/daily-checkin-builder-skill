# GitHub Actions 工作流标准

## 生成触发器

生成 `.github/workflows/daily-checkin.yml`，同时提供手动和定时入口：

    on:
      workflow_dispatch:
      schedule:
        - cron: "17 7 * * *"
          timezone: "Asia/Shanghai"

使用五字段 POSIX cron。把分钟默认设为非 0 值，避免整点高峰。使用用户确认的 IANA 时区；未确认时区时不得声称计划时间准确。

在部署文档中说明：

- 定时工作流只从默认分支运行，工作流文件必须存在于默认分支；
- 平台高负载时可能延迟，任务不应依赖秒级准时；
- 使用夏令时的 IANA 时区可能出现跳过或重复的本地时间，应选择合适时刻并依赖“已签到”幂等判定；
- 公共仓库长期无活动时定时工作流可能被自动禁用，应说明重新启用方法；
- 修改 cron 或时区后先手动运行验证。

## 限制权限与重叠

在工作流顶层设置最小权限：

    permissions:
      contents: read

若没有明确需要，不授予 `write`、`id-token`、`packages`、`issues` 或 `pull-requests` 权限。

设置稳定的并发组，防止相同仓库和工作流的签到任务重叠。默认使用 `cancel-in-progress: false`，避免取消一个可能已提交签到请求但尚未验证结果的运行。用作并发组的表达式不得包含秘密。

为作业设置合理的 `timeout-minutes`。让应用自身也设置 HTTP 超时，不能只依赖作业超时。

## 固定运行环境

- 选择明确的 `ubuntu-*` runner；
- 固定 Python 或 Node 的受支持版本；
- 使用官方或可信来源的 Action；
- 固定到明确版本；安全要求较高时固定到经核验的完整提交 SHA，并在注释中写对应发布版本；
- 不得猜测或编造提交 SHA；
- 使用依赖锁文件或带版本约束的依赖清单；
- 通过运行时设置 Action 的依赖缓存，不缓存 Cookie、Token、`.env`、HAR 或运行响应。

优先使用项目自身的通知模块，避免为通知引入来源不明的第三方 Action。

## 按固定顺序执行

按以下顺序组织步骤：

1. 检出代码；
2. 设置明确的 Python 或 Node 版本并启用依赖缓存；
3. 安装锁定的依赖；
4. 运行单元测试或最低限度的离线自检；
5. 从 Secrets 映射认证环境变量；
6. 调用与本地、青龙相同的业务入口；
7. 在需要时发送只含脱敏摘要的通知；
8. 保留应用的非零退出码。

不得用 `continue-on-error: true` 掩盖签到失败。若通知步骤允许失败，必须明确只对通知步骤设置策略，并保留核心签到结果。

## 注入秘密

把秘密配置在仓库或环境的 GitHub Secrets 中，通过步骤级 `env` 映射到应用所需变量。只把非敏感的时区、重试次数和日志级别放入 Variables 或普通 `env`。

执行以下保护：

- 不把 Secrets 拼入命令行参数、矩阵、作业名、并发组或输出；
- 不执行 `env`、`printenv`、`set -x` 或打印完整上下文；
- 不把秘密写入 `GITHUB_ENV`、`GITHUB_OUTPUT`、缓存或 artifact；
- 不在工作流中提供真实默认值；
- 多账号使用一个结构化 Secret，并由应用校验 JSON；
- 对可由用户控制的 `workflow_dispatch` 输入执行白名单校验，不把输入直接拼接成 shell 命令。

日志和异常统一按 [安全规范](security.md) 脱敏。

## 隔离测试与真实签到

让默认测试只使用 mock 和脱敏 fixture，不访问真实站点。不得在 `pull_request` 或来自 fork 的工作流中自动执行真实接口测试。

若项目提供 live test：

- 要求用户明确授权并手动设置 `LIVE_TEST=1`；
- 只允许受保护的手动运行或明确的生产定时作业启用；
- 不让 fork 获得仓库 Secrets；
- 在条件表达式中同时检查触发事件和显式开关；
- 使用专用低权限测试账号和安全频率。

不要把生产签到等同于测试。生产定时任务只执行经离线测试通过的统一入口。

## 编写部署文档

在 `DEPLOY_GITHUB.md` 中逐项说明：

1. 在 Settings → Secrets and variables → Actions 创建哪些 Secrets；
2. 如何从 Actions 页面执行 `workflow_dispatch`；
3. 如何修改 cron、`timezone` 和避峰分钟；
4. 如何查看步骤日志和应用状态摘要；
5. 如何判断定时延迟或被禁用；
6. 如何轮换过期 Cookie、Token 或通知凭据；
7. 如何临时禁用工作流或删除 `schedule`；
8. 如何确认失败返回非零退出码；
9. 如何更新固定版本的 Action 和依赖。

若站点提供交互登录，不要在 Actions 定时工作流中执行登录或显示二维码。让操作者在本机手动运行站点专用登录入口；只有本机已安装并登录 GitHub CLI 时，才允许程序通过标准输入调用 `gh secret set` 更新目标 Secret。禁止使用命令参数、工作流输出、artifact 或日志传递 Cookie。把确切登录命令、Secret 名称和轮换步骤写入 `docs/cookie-setup.md`。

## 交付前验证

- 使用 YAML 解析器读取工作流；
- 使用可用的 GitHub Actions lint 工具检查表达式和键名；
- 确认同时存在 `workflow_dispatch`、`schedule`、IANA `timezone`、最小权限、并发、超时和明确运行时；
- 确认测试先于真实签到；
- 搜索工作流，确认没有真实秘密、调试回显和专属生产值；
- 用缺失 Secret 的场景验证应用返回 `CONFIG_ERROR` 和非零退出码。
