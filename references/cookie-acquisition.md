# 站点专用 Cookie 获取与登录交付

本文件是生成规则，不是交付给所有网站共用的 Cookie 教程。每个生成项目必须根据该站点的实际 Network、正式登录接口或 App 登录流程生成独有的 `docs/cookie-setup.md`。证据不足时把获取方式列为阻塞项，不得给出似是而非的 F12 路径、Cookie 名称、Console 指令或登录接口。

## 选择获取模式

按证据依次选择一种模式，并在 `docs/cookie-setup.md` 写入 `Acquisition mode`：

1. `password_login`：站点提供账号密码表单。默认让用户在可视浏览器直接输入；用户明确选择自动填充时，账号密码只从受保护环境变量进入已验证选择器。提交前后出现的人机验证由用户在同一页面完成。
2. `otp_login`：站点提供短信或邮箱验证码登录。用户在可视页面请求并输入验证码；程序不读取短信、邮箱、剪贴板或一次性验证码。出现人机验证时保持同一页面等待用户完成。
3. `interactive_login`：站点或 App 提供已证实的二维码、设备授权、OAuth 或其他正常交互登录。生成站点专用手动登录入口，让操作者本人完成确认，程序有界轮询正式结果。
4. `network`：没有可安全实现的交互登录入口，但用户可在正常登录浏览器中查看已认证请求。必须从该站点 Network 取证确定精确请求，而不是泛称“随便找一个请求”。
5. `console`：仅当证据确认所有必需 Cookie 都可由同源页面 JavaScript 读取时使用。只生成读取明确 Cookie 名称的最小表达式；需要 `HttpOnly` Cookie 时不得使用 Console，改用 `network`。
6. `not_applicable`：目标实现不使用 Cookie。文档仍要说明实际认证方式和为什么不需要 Cookie 环境变量。

如果正常状态或刷新响应会更新 Cookie，业务运行时继续用每账号独立的内存 jar 接收 `Set-Cookie`。这属于会话续用，不能替代初始 Cookie 获取方案。

## 编写站点专用 Network 指引

只有看到脱敏 Network/HAR 或在经授权会话中完成正常取证后，才写具体步骤。`docs/cookie-setup.md` 必须包含：

- 站点域名、登录页与签到页；
- 浏览器开发者工具中的面板、筛选词，以及目标请求的精确方法和脱敏路径；
- 为什么该请求代表已登录会话，如何避免选择广告、埋点或第三方请求；
- 在 **Headers → Request Headers** 中要读取的头，以及经过证据确认的 Cookie 名称白名单；
- 最终字符串的脱敏形状，例如注明由 `session` 与 `csrf` 两个名值对组成且二者的值均为 `<REDACTED>`，并说明是否保留顺序、是否 URL 解码、是否删除 `Path`、`Expires` 等 `Set-Cookie` 属性；
- 最终环境变量的确切名称，单账号与多账号如何填写，GitHub Actions、青龙或本地中用户实际选择的平台如何保存；
- 用无副作用状态查询验证的方法、过期表现、更新步骤和撤销方式。

不要让用户把 Copy as cURL、完整请求头或真实输出粘贴到对话。Cookie 值从浏览器直接进入受保护的 Secret；文档、截图、命令行参数和日志只出现占位符。

## 编写站点专用 Console 指令

先从实际页面脚本和 Cookie 属性确认所需名称可由 `document.cookie` 读取。生成的 JavaScript 必须：

- 固定白名单名称，不输出该域下全部 Cookie；
- 只读取当前同源页面，不请求外部地址、不写剪贴板、不读取 localStorage、IndexedDB、浏览器扩展或配置文件；
- 返回与目标环境变量完全一致的字符串形状；
- 对缺失名称明确报错，不把 `undefined` 当成有效值；
- 在文档中列出预期的脱敏输出示例和后续处理步骤。

若任一必需 Cookie 是 `HttpOnly`、页面 CSP/权限不允许安全执行，或名称与编码未证实，不生成 Console 指令，改用精确的 Network 指引或交互登录。

## 生成交互登录入口

读取 [账号密码、验证码与人机验证交互登录](interactive-login.md)，参考“任务脚本只启动登录业务、登录业务负责获取会话、存储适配器负责写入平台”的分层方式。仅实现已证实的站点正常流程：

1. 请求二维码、设备码或正式授权 URL；
2. 向用户展示二维码或官方 URL，不展示登录凭据；
3. 以固定间隔、有界次数轮询正式状态，处理未扫描、待确认、过期、拒绝与成功；
4. 仅在成功响应中读取 `Set-Cookie` 或正式令牌字段；
5. 解析并校验站点分析列出的必需 Cookie 名称，拒绝空值和意外域；
6. 可选执行一次无副作用的第一方请求以接收正常补充 Cookie；
7. 通过所选平台的安全存储适配器新增或更新目标环境变量，全程不打印秘密；
8. 返回非敏感账号别名与成功/失败状态，临时会话只保存在内存并在退出时清理。

登录入口必须由操作者在自己的桌面电脑手动运行，不能进入 GitHub Actions 的定时任务或青龙 cron。账号密码、OTP 与人机验证在同一本地 headed 浏览器 context 中完成；轮询 GET 可以按正式协议有界重试。目标为青龙时，由本地助手通过已验证 OpenAPI 写入最终 Cookie，青龙端不安装浏览器。不得重复提交确认、读取短信/邮箱、自动处理 MFA、求解安全挑战或提取挑战 Token。

### 平台持久化

- **青龙**：只有确认当前青龙版本和 OpenAPI 后才生成客户端。Client ID/Secret 从受保护环境变量读取；用环境变量查询、新增、更新接口按非敏感账号别名定位目标值。限制 API 基址为配置的青龙实例，设置超时，校验响应，不在失败回退中打印 Cookie。
- **GitHub Actions**：交互登录应在操作者本机执行；若已安装并登录 GitHub CLI，可把 Cookie 通过标准输入传给 `gh secret set`。不得把 Cookie 放在 `--body`、shell 历史、工作流日志或 Actions artifact 中。
- **本地**：进程不能修改父 shell。优先让登录入口在同一进程启动一次任务，或使用用户明确选择的系统秘密存储/权限受限且已被忽略的本地文件加载器。不要声称子进程能永久设置父进程环境变量。

若目标平台没有经过验证的安全写入方式，文档必须明确说明限制，并给出站点专用字符串到该平台 Secret 字段的精确人工步骤。

## 测试与验收

对交互登录和 Cookie 设置至少离线验证：

- 账号密码手动输入/受保护自动填充、OTP 等待与二维码/设备码流程；
- 人机验证在输入前、输入后和提交后出现，用户完成后仍使用同一 context；
- 有界轮询与取消；
- 多个 `Set-Cookie` 合并、删除属性、Cookie 名称白名单和账号隔离；
- 平台环境变量新增、更新、API 失败和权限失败；
- 所有日志、异常、测试失败和 mock fixture 不含可复用秘密；
- 默认 CI 不调用真实登录接口，也不生成真实二维码。

## 结构参考：BiliBiliToolPro

可参考固定提交 `d552d69817cf0a07893f422c5210b39303904b5a` 的分层思路：

- [`bili_task_login.sh`](https://github.com/RayWangQvQ/BiliBiliToolPro/blob/d552d69817cf0a07893f422c5210b39303904b5a/qinglong/DefaultTasks/bili_task_login.sh) 只启动手动 `Login` 任务，不把登录混入日常 cron 业务；
- [`LoginTaskAppService.cs`](https://github.com/RayWangQvQ/BiliBiliToolPro/blob/d552d69817cf0a07893f422c5210b39303904b5a/src/Ray.BiliBiliTool.Application/LoginTaskAppService.cs) 分离二维码登录、补充 Cookie 与持久化步骤；
- [`LoginDomainService.cs`](https://github.com/RayWangQvQ/BiliBiliToolPro/blob/d552d69817cf0a07893f422c5210b39303904b5a/src/Ray.BiliBiliTool.DomainService/LoginDomainService.cs) 生成二维码、轮询官方状态、从成功响应合并 `Set-Cookie`，并在青龙平台调用环境变量 API 新增或更新值。

只借鉴“手动登录入口—正式登录会话—平台存储适配器”的结构。不得复制 Bilibili 的路径、状态码、Cookie 名称或青龙 API 假设到其他站点；每个值都要重新取证。该参考实现在持久化失败时可能把 Cookie 输出到日志，生成项目不得复制这种回退行为，只能报告脱敏错误和精确恢复步骤。
