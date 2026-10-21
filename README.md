# iOS 专项测试工作台 0.1.0

这是独立的全链哨兵社区插件。SSH、设备状态、应用分析和任务执行都在本插件内，不依赖旧版平台的苹果设备页面。不修改哨兵主程序，不接 Docker socket，不需要 privileged，也不需要镜像仓库推送。

源码仓库：[laobiaoaaa/sentinel-ios-workbench](https://github.com/laobiaoaaa/sentinel-ios-workbench)。发行包包含 `plugin.json`、`Dockerfile`、完整构建上下文和界面，插件主机从上传包现场构建，无需推送镜像。

已完成 Linux amd64 / Docker / Python 3.12 的构建与隔离验收，包括 MCP、SSH 转发、真实代理抓改包、UI 资源和退出清理。具体检查和环境边界见 [VALIDATION.txt](./VALIDATION.txt)。尚未完成本插件的 iPhone 真机及目标 App 兼容验收。

## 构建和安装

从 [Releases](https://github.com/laobiaoaaa/sentinel-ios-workbench/releases) 下载 `sentinel-ios-workbench-0.1.0.zip`，在哨兵“设置 → 插件 → 上传插件包”选择它，确认清单并勾选允许 Dockerfile 构建。安装后打开“苹果测试”界面，保存 SSH 配置，等待容器重建后连接设备。给会话启用本插件的工具权限后，模型也可直接调用这 19 个工具。

手动构建调试：

```
docker build -t sentinel-plugin/local.sentinel.ios-workbench:0.1.0 .
docker run --rm -p 127.0.0.1:7801:7801 -v ios-plugin-data:/data -v ios-plugin-artifacts:/artifacts sentinel-plugin/local.sentinel.ios-workbench:0.1.0
```

插件主机安装时自动完成同类构建和容器生命周期。基础镜像使用 docker.1ms.run；Python 依赖使用已获准的阿里云国内镜像。构建参数 PIP_INDEX_URL 在 manifest 的 build.args 中明确给出，也可传入其他获准使用的国内镜像。依赖都装在容器内；bcrypt 固定为 4.0.1，避免 mitmproxy 11 使用的 passlib 与 bcrypt 5 不兼容而无法启动。

插件健康检查不要求手机在线。GET /healthz、POST /mcp，以及 /ui/* 由同一个 0.0.0.0:7801 HTTP 服务提供。UI 使用官方 v2.1.6 SDK 和基础 CSS；无外网请求、Cookie、localStorage 或 /api 私有接口。

## 设备连接

在插件界面填写 SSH 地址、端口（默认 22）、用户名（默认 root），以及密码或 PEM 私钥。秘密字段仅经 SDK config.save 保存到插件主机，再通过 PLUGIN_* 环境变量注入，工具不接收或回显 SSH 秘密；空白秘密输入表示保持已有值。保存配置会重建容器、断开已有任务，请在任务结束后保存。

第一次点击连接会固定该地址和端口的 SSH 主机密钥到 /data/known_hosts，以后变化会拒绝连接。可预填 SHA256 指纹。读取指纹按钮只握手，不认证也不建立新信任。连接后读取真实型号、系统版本、架构、UID、工具路径；普通 Linux SSH 连通不等同于 iOS 设备验证通过。

本版本每个插件配置一个当前 SSH 目标。首次连接时输入凭据，之后模型通过工具即可使用该连接。不会自动导入旧平台的密文凭据，也不会安装软件、修改设备代理、信任证书、越狱或重启设备。

## 实际测试流程

1. 调用 ios_device_connect，检查设备信息与工具能力；ios_apps_list 分页列应用。
2. 客户端/综合任务用 ios_test_start，自动从设备拷贝指定应用，分析配置、Mach-O、内嵌脚本和资源，并观察支持的运行时网络函数。任务的每一步都有实际状态。
3. 独立 IPA 可在插件界面分片导入（最大512MiB），完全通过 MCP 工具传输；不依赖包外宿主路径。
4. ios_hook_start 可选 network、crypto、storage。通过 SSH 转发连接设备现有 Frida 服务，先做真实协议探测，再选择内置 Frida 17.2.17 或 16.7.19 运行时。先附加运行中的目标；目标未运行时尝试启动。不同越狱布局读取工具能力，但不凭布局标签保证注入成功。
5. ios_dump_start 复制应用并导出当前进程加载的加密区域。严格核验模块、架构、偏移和输出；未加载扩展、其它架构和非法文件不能冒充脱壳完成。大IPA分为48MiB片段，按编号拼接，校验 dump-manifest.json 中的SHA256。
6. ios_proxy_start 启动 mitmproxy 与 SSH 反向隧道，进度中显示手机127.0.0.1端口。设备/App必须实际使用该代理；HTTPS需要信任生成的公共CA。私有CA密钥仅在/data/proxy-ca。证书绑定、自定义网络栈和应用层加密不自动由代理解决。任务结束只清理本插件代理与隧道。
7. ios_proxy_rules_set 设置明确 URL 匹配的请求头/请求体/响应体改写规则。Hook crypto 还支持对进程内 CCCrypt 加密输入做等UTF-8字节长度的明确文本替换；事件标为 crypto_input_mutation，不代表已修改网络请求，也可能命中本地存储加密。不会采集密钥或IV。自定义算法、CryptoKit、签名及其它未覆盖函数需要后续专项脚本适配，不能宣称通用解密。二进制观察最多保留8KiB，并标出原长度、实际采集长度、是否截断和读取是否成功。
8. 服务端以实际观察的接口为依据，用 ios_api_check 发送基线与最多两个显式身份对照请求。界面与模型都可提供方法、正文和 base_headers 通用请求头（例如 Content-Type）；各身份分别通过 headers/compare_headers 覆盖，头名不区分大小写。所有请求共用方法、URL和正文。基线头、URL/body 中的身份参数需由调用者清除，才是匿名请求，不会自动删除业务字段。每个身份使用独立HTTP客户端，不共享Cookie、不自动跟随跳转。没有账号仍可执行基线检查；身份对比没有材料时标记未验证，不伪造结论。
9. 用 ios_job_status 读进度、真实失败原因和产物；ios_job_stop 取消；ios_job_delete 删除已结束任务和证据。最多3个不同类别任务，设备分析互斥，保留100个任务；进程重启将运行任务标为中断，不偷偷重新测试。

工具描述和结构化参数独立于预设 Agent。启用MCP及该插件权限后，预设为空也可调用。模型仍需选择目标/发起任务；不会因安装插件便自行测试设备。任务引擎执行工具内部的固定流程，不要求模型逐条记住全部步骤。

## 工具能力与结果边界

- 静态提取的是接口候选，动态观察证明发生过调用，服务端请求比较提供验证材料；这些均不自动等于漏洞。
- 静态 Mach-O 分析不是反编译器，不恢复原始源码。加密文件仍可检查可读配置/资源，代码覆盖明确受限。
- 内置两套 Frida 客户端不是所有 iOS/越狱版本的兼容保证。设备端服务、Gadget、调试权限及目标App条件必须真实可用；不兼容返回原因。
- rootless/rootful工具路径探测不等于完整 roothide 支持。未知环境仍可使用SSH和可读取应用资料，动态分析要以实际连接/注入结果为准。
- 抓包不涵盖未经过代理且未命中已支持Hook点的通信；0条记录不代表安全。默认只观察，改包必须给出具体规则。
- network Hook 观察的是受支持的任务创建方法和 TLS 函数；NSURLRequest.HTTPBody 之外的流式正文、独立上传NSData、请求头和响应回调未完整覆盖，任务创建也不证明已经发送。crypto 分块事件没有自动拼成完整协议会话，不把零散明文与任意密文硬配对。
- 自动任务不会主动向所有字符串候选发送请求，也不会将状态码相同直接报为未授权/越权。
- IPA、响应、Hook、报告可能包含测试数据；保存在插件自己的/data或/artifacts，不发送到第三方服务。SSH秘密不出现在日志和返回值中。
- 每个产物不超过50MiB。UI文本预览受宿主1MiB上限约束，大文件通过宿主产物下载入口获取。
- 产物不会自动写进漏洞中枢。需要入库时，当前会话模型使用平台原有 vuln_submit，插件不直接写平台数据库。
- 权限是平台的插件级授权；UI工具调用与模型调用不是同一条审批路径，但使用同一执行器、任务互斥和结果逻辑。
- 本版本没有苹果屏幕远控/自动点击、任意应用自动越狱/签名/Gadget植入、设备端软件自动安装功能。

## 运行检查

```
python -m unittest discover -s tests -p 'test_*.py' -v
node tests/test_ui.mjs
node tests/test_hooks.mjs
```

Python测试包括真实loopback SSH握手/SFTP/转发夹具、真实IPA和Mach-O解析、HTTP MCP、隔离HTTP身份对照与取消/重启边界。测试夹具不能替代iPhone真机兼容验收；具体构建与验收记录见交付的验证说明。

第三方依赖分别遵守自身许可。官方 SDK 和 base.css 来自 Full-Chain-Sentinel-System v2.1.6（5ad797f5ed29bdeacbe8e3346dad3a31fb552c2f）的插件模板，版权归原作者。
