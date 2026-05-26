# 常规漏洞

## 跨站脚本
当前覆盖反射型、存储型、DOM型、模板引擎不安全渲染、文件上传导致的存储型XSS、第三方组件XSS、WebSocket XSS、postMessage XSS、CSP、HttpOnly、输出编码等常见场景。

XSS的本质是不可信数据进入浏览器页面执行上下文后，被当作HTML、脚本、URL或可执行DOM操作解析。修复优先按输出上下文处理数据，普通文本使用HTML实体编码或安全DOM API，URL/属性/JavaScript/CSS等位置使用对应编码与白名单校验；CSP、HttpOnly、输入过滤是辅助防护，不能替代根因修复。

已覆盖类型

| 分类 | 已有场景 | 结论 |
| --- | --- | --- |
| 反射型XSS | GET/POST参数、String直出、Content-Type差异 | 覆盖请求即触发、响应类型影响浏览器解析的基础成因 |
| 反射型安全写法 | 前后端白名单、CSP、HTML正文输出编码、HttpOnly | 覆盖常见防护，并明确白名单/CSP/HttpOnly不是根因修复 |
| 存储型XSS | 表单内容、User-Agent持久化、表格不安全渲染 | 覆盖先存储后触发，也包含Header进入持久化链路 |
| 存储型安全写法 | 表格渲染阶段输出编码 | 说明数据库可保存原始值，进入页面前必须按上下文编码或净化 |
| DOM型XSS | innerHTML、localStorage、hash跳转、location、eval、document.write | 覆盖常见Source到Sink的客户端链路 |
| DOM型安全写法 | textContent、URL协议白名单、命令映射、createTextNode | 覆盖DOM侧推荐修复方式 |
| 其他场景 | Thymeleaf `th:utext`、文件上传、jQuery/Swagger/UEditor、WebSocket、postMessage | 覆盖模板、文件、供应链与HTML5通信场景 |

模块覆盖整体符合综合性靶场定位。JSONP类XSS/脚本回调污染在项目中已有跨域模块承载，不建议在XSS模块重复堆叠；后续如需扩展，可优先补充“属性上下文XSS”“JavaScript字符串上下文XSS”“富文本白名单净化绕过对比”“Markdown/预览器XSS”等更贴近真实业务的场景。

### 反射型XSS测试

页面：`/xss/reflect/vul`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| GET型JSON返回 | `GET /xss/reflect/vul1?payload=<img src=x onerror=alert(1)>` | HTML事件载荷 | 接口返回payload；页面结果区使用不安全HTML渲染时可触发 |
| POST型JSON返回 | `POST /xss/reflect/vul1` | `payload=<img src=x onerror=alert(1)>` | 接口返回payload；验证POST入口同样可控 |
| String直出 | `GET /xss/reflect/vul2?payload=<script>alert(1)</script>` | 脚本标签 | 响应体直接包含payload，用于观察浏览器解析行为 |
| text/plain | `GET /xss/reflect/vul3?type=plain&payload=<script>alert(1)</script>` | 脚本标签 | `Content-Type`为`text/plain;charset=utf-8`，浏览器按文本展示 |
| text/html | `GET /xss/reflect/vul3?type=html&payload=<script>alert(1)</script>` | 脚本标签 | `Content-Type`为`text/html;charset=utf-8`，浏览器按HTML解析 |
| 流量包/示例载荷 | 页面下拉与按钮 | 标签探测、流量劫持、Cookie读取、页面篡改 | 示例可填充，按钮可提交 |

### 反射型安全场景测试

页面：`/xss/reflect/safe`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 前端白名单 | `GET /xss/reflect/safe1?type=frontEnd&payload=<script>alert(1)</script>` | 非白名单字符 | 页面按钮触发时前端拦截；直接请求仍会返回，说明前端不是安全边界 |
| 后端白名单 | `GET /xss/reflect/safe1?type=backEnd&payload=<script>alert(1)</script>` | 非白名单字符 | 返回“输入内容包含非法字符，请检查输入” |
| CSP Header | `GET /xss/reflect/safe2?payload=<script>alert(1)</script>` | 脚本标签 | 响应包含`Content-Security-Policy`，用于演示防御层 |
| HTML正文手动编码 | `GET /xss/reflect/safe3?type=manual&payload=<img src=x onerror=alert(1)>` | HTML事件载荷 | 返回实体编码后的内容，不作为标签执行 |
| Spring HTML编码 | `GET /xss/reflect/safe3?type=spring&payload=<img src=x onerror=alert(1)>` | HTML事件载荷 | 返回Spring编码后的内容 |
| HttpOnly | `GET /xss/reflect/safe4?payload=<script>alert(document.cookie)</script>` | Cookie读取载荷 | 返回设置结果，响应`Set-Cookie`应带`HttpOnly` |

### 存储型XSS测试

页面：`/xss/store`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 原生写入 | `POST /xss/store/vul` | `payload=<img src=x onerror=alert(1)>` | 写入成功，漏洞表格不安全渲染时可触发 |
| User-Agent持久化 | `POST /xss/store/vul` | Header `User-Agent: <img src=x onerror=alert(1)>` | UA字段被持久化，漏洞表格不安全渲染时可触发 |
| 列表查询 | `GET /xss/store/getXssList?page=1&limit=10` | 无 | 返回分页数据，包含刚写入记录 |
| 安全表格 | 页面安全场景表格 | 已存储恶意内容 | Content与User-Agent经HTML实体编码展示，不执行脚本 |
| 删除记录 | `POST /xss/store/deleteOne?id=<记录ID>` | 已存在ID | 返回删除成功，页面表格记录消失 |

### DOM型XSS测试

页面：`/xss/dom`

| 场景 | 入口 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| innerHTML | 多种代码场景/innerHTML | `123<img src=x onerror=alert(1)>123` | 结果区使用`innerHTML`写入，事件载荷可执行 |
| LocalStorage | 多种代码场景/LocalStorage | `123<img src=x onerror=alert(1)>123` | 先写入`localStorage`，再读取并不安全写入DOM |
| hash跳转 | `/xss/dom/href#javascript:alert(1)` | `javascript:`伪协议 | 页面读取`location.hash`并赋值给`location.href` |
| location | 多种代码场景/location对象 | `javascript:alert(1)` | 直接赋值给`window.location`，用于演示危险URL Sink |
| eval | 多种代码场景/eval执行 | `alert(1)` | 用户输入被`eval`执行 |
| document.write | 多种代码场景/document对象 | `<img src=x onerror=alert(1)>` | `document.write`写入HTML并可能触发 |
| 文本安全输出 | 安全场景/文本输出 | `<img src=x onerror=alert(1)>` | 使用`textContent`，作为文本展示 |
| URL安全校验 | 安全场景/URL跳转 | `javascript:alert(1)` | 拦截危险协议 |
| 替代eval | 安全场景/替代eval | `alert(1)` | 命令白名单无匹配，拒绝执行 |
| DOM API | 安全场景/DOM API | `<img src=x onerror=alert(1)>` | 使用文本节点展示，不执行脚本 |

### 其他XSS场景测试

页面：`/xss/other`

| 场景 | 请求/入口 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| Thymeleaf `th:utext` | `GET /xss/other/vul2OtherTemplate?type=html&payload=<img src=x onerror=alert(1)>` | HTML事件载荷 | `th:utext`按HTML渲染，演示模板不安全输出 |
| Thymeleaf `th:text` | `GET /xss/other/vul2OtherTemplate?type=text&payload=<img src=x onerror=alert(1)>` | HTML事件载荷 | `th:text`实体转义，作为文本展示 |
| HTML文件上传 | `POST /xss/other/vul1Upload?type=html` | `xss.html` | 返回可访问文件路径，访问后按浏览器解析策略触发/展示 |
| SVG文件上传 | `POST /xss/other/vul1Upload?type=svg` | `xss.svg` | 返回可访问文件路径，用于验证可解析文件风险 |
| XML文件上传 | `POST /xss/other/vul1Upload?type=xml` | `xss.xml` | 后端解析成功后落盘，返回访问路径 |
| PDF文件上传 | `POST /xss/other/vul1Upload?type=pdf` | `xss.pdf` | 返回访问路径；PDF脚本执行能力取决于阅读器实现 |
| jQuery组件XSS | `/xss/other/jquery-xss` | 页面内示例 | 页面可打开，用于演示旧版jQuery风险 |
| Swagger UI组件XSS | `/swagger-ui/index.html?configUrl=...` | 恶意配置URL示例 | 页面可打开，用于供应链组件风险演示 |
| UEditor | `/ueditor`、`/ueditor/config` | 编辑器上传/配置 | 页面与配置接口可访问，上传接口返回UEditor格式结果 |
| WebSocket XSS | 页面HTML5特性/WebSocket XSS | `<img src=x onerror=alert(1)>` | 服务端广播消息，前端用`innerHTML`写入消息区 |
| postMessage XSS | 页面HTML5特性/PostMessage XSS | `<img src=x onerror=alert(1)>` | 接收窗口未校验origin且用`innerHTML`写入消息 |

## CSRF

当前覆盖基于登录态 Cookie 的状态变更请求、CSRF Token 校验、Origin/Referer 辅助校验三类核心场景。模块重点演示“用户已登录 + 浏览器自动携带凭证 + 服务端缺少请求来源或意图校验”这一条攻击链。

CSRF的本质是攻击者诱导已登录用户访问恶意页面或触发恶意请求，浏览器自动携带目标站点 Cookie/Session 等凭证，服务端误以为请求来自用户本人，从而执行转账、改密、绑定账号等敏感操作。修复优先使用框架内置 CSRF 防护或不可预测的 CSRF Token；Origin/Referer、SameSite Cookie、二次确认、操作审计是重要补充，但不应替代 Token 和服务端鉴权。

已覆盖类型

| 分类 | 已有场景 | 结论 |
| --- | --- | --- |
| 原生漏洞 | `GET /csrf/vul` 只依赖登录态执行转账 | 覆盖最基础的跨站请求伪造风险，GET 状态变更会放大问题 |
| Token防护 | `GET /csrf/safe1` 校验 Session 中的随机 Token | 覆盖 CSRF 的主流修复方式 |
| 来源校验 | `GET /csrf/safe2` 校验 Origin/Referer 的协议、域名、端口 | 适合作为 Token 之外的辅助防线 |
| 安全编码提示 | 页面说明 SameSite、二次确认、短有效期、审计 | 覆盖业务侧加固建议 |

模块覆盖符合综合性靶场定位。后续如需增强，可补充“POST 表单自动提交 PoC 页面”“JSON CSRF/简单请求 Content-Type 限制”“SameSite Cookie 对比”“Origin 缺失策略”“Referer 前缀匹配绕过反例”等专项场景。当前模块保留为基础成因、Token 修复和来源辅助校验主线即可。

### CSRF漏洞场景测试

页面：`/csrf`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 页面访问 | `GET /csrf` | 已登录会话 | 页面正常打开，展示原生漏洞、Token防护、Origin/Referer辅助校验和代码片段 |
| 原生转账 | `GET /csrf/vul?receiver=zhangsan&amount=100` | 已登录会话 | 返回当前登录用户、收款人和金额，说明仅凭 Cookie/Session 即可触发状态变更 |
| 未登录访问 | `GET /csrf/vul?receiver=zhangsan&amount=100` | 无登录会话 | 跳转登录页或被认证流程拦截 |
| GET状态变更 | 页面“漏洞场景：原生漏洞场景”表单 | `receiver=zhangsan&amount=100` | 点击后以 GET 打开转账结果，便于观察 CSRF 风险 |

### CSRF安全场景测试

页面：`/csrf`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 获取Token | `GET /csrf/getCsrfToken` | 已登录会话 | 返回随机 `csrfToken`，并写入 Session |
| Token缺失 | `GET /csrf/safe1?receiver=zhangsan&amount=100` | 不带 `csrfToken` | 返回 `success=false` 和 “Token失效！” |
| Token错误 | `GET /csrf/safe1?receiver=zhangsan&amount=100&csrfToken=bad` | 错误Token | 返回 `success=false` 和 “Token失效！” |
| Token正确 | `GET /csrf/safe1?receiver=zhangsan&amount=100&csrfToken=<session token>` | Session中生成的Token | 返回当前用户、收款人、金额和Token |
| Origin/Referer缺失 | `GET /csrf/safe2?receiver=zhangsan&amount=100` | 不带来源头 | 返回 `success=false` 和 “Origin/Referer无效！” |
| Origin恶意来源 | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Origin: http://evil.example` | 返回 `success=false` |
| Origin同源 | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Origin: http://127.0.0.1` | 返回当前用户、收款人和金额 |
| Referer同源 | `GET /csrf/safe2?receiver=zhangsan&amount=100` | Header `Referer: http://127.0.0.1/csrf` | 返回当前用户、收款人和金额 |

## SQL注入

当前覆盖JDBC原生拼接、伪预编译拼接、JdbcTemplate拼接、参数化查询、MyBatis动态SQL、Hibernate HQL/原生SQL、JPA JPQL/动态排序等常见开发栈。

SQL注入的本质是不可信输入进入SQL语法结构并改变原SQL语义；修复优先使用参数化查询，列名、表名、排序方向等SQL结构必须使用枚举或白名单映射。黑名单、类型校验、ESAPI编码只作为辅助方案，不应作为首选修复方案。

已覆盖类型

| 分类 | 已有场景 | 结论 |
| --- | --- | --- |
| JDBC | 原生SQL拼接、伪预编译拼接、JdbcTemplate拼接 | 覆盖基础漏洞成因，适合新手理解 |
| JDBC安全写法 | PreparedStatement、JdbcTemplate参数绑定 | 覆盖常规DML安全修复 |
| 辅助方案 | 黑名单、数据类型校验、ESAPI encodeForSQL | 可保留，但页面应强调非首选修复 |
| 特殊结构与利用链 | ORDER BY、LIKE、LIMIT、二次SQL注入、UNION回显 | 覆盖参数绑定无法直接处理SQL结构，以及存储型链路和数据回显利用 |
| MyBatis | 内置方法、自定义`#{}`、`${}` ORDER BY/LIKE/IN、foreach | 覆盖MyBatis典型误区 |
| Hibernate | 原生SQL、HQL、setParameter | 覆盖ORM下仍会注入的情况 |
| JPA | JPQL、动态排序、命名参数、Criteria白名单 | 覆盖JPA常见风险点 |

### JDBC漏洞场景测试

页面：`/sqli/jdbc/jdbcVul`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 原生拼接-查询 | `GET /sqli/jdbc/vul1?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | 漏洞场景返回多条或异常中泄露SQL行为 |
| 原生拼接-新增报错 | `GET /sqli/jdbc/vul1?type=add` | `password=1' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) AND '1'='1` | 返回数据库报错信息或执行异常 |
| 伪预编译 | `GET /sqli/jdbc/vul2?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | 仍可被注入，证明先拼SQL再prepare无效 |
| JdbcTemplate拼接 | `GET /sqli/jdbc/vul3?type=select&id=1 OR 1=1` | `id=1 OR 1=1` | 仍可被注入 |
| 流量包下载 | 页面右上角流量分析下拉 | 延时/布尔/报错/Xpath | 选择后应下载对应`pcapng`文件 |

### JDBC安全与辅助场景测试

页面：`/sqli/jdbc/jdbcSafe`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| PreparedStatement | `GET /sqli/jdbc/safe1?type=select&id=1 OR 1=1` | 非数字或注入payload | 不执行注入语义，返回参数错误或查询失败 |
| JdbcTemplate参数绑定 | `GET /sqli/jdbc/safe2?type=select&id=1 OR 1=1` | 注入payload | 不执行注入语义 |
| 黑名单辅助 | `GET /sqli/jdbc/safe3?type=select&id=1 and sleep(5)` | 含黑名单关键字 | 拦截并提示“黑名单检测到非法SQL注入” |
| 数据类型校验 | `GET /sqli/jdbc/safe4?id=1' or '1'='1` | 字符型注入 | 拒绝非整数输入 |
| ESAPI辅助 | `GET /sqli/jdbc/safe5?id=1' or '1'='1` | 字符型注入 | 编码后不应改变SQL语义，但不作为首选修复验收 |

### JDBC特殊场景测试

页面：`/sqli/jdbc/jdbcSpecial`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| ORDER BY拼接 | `GET /sqli/jdbc/special1-OrderBy?type=raw&field=username and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)%23` | 动态排序字段注入 | 漏洞路径出现异常或泄露 |
| ORDER BY占位符误区 | `GET /sqli/jdbc/special1-OrderBy?type=prepareStatement&field=username` | 合法字段 | 不能真正按字段排序，用于说明占位符不能绑定SQL结构 |
| ORDER BY白名单 | `GET /sqli/jdbc/special1-OrderBy?type=writeList&field=username` | 合法字段 | 正常返回排序结果 |
| ORDER BY白名单拦截 | `GET /sqli/jdbc/special1-OrderBy?type=writeList&field=username desc` | 非白名单字段 | 返回字段不合法 |
| LIKE拼接 | `GET /sqli/jdbc/special2-Like?type=raw&keyword=1' OR '1'='1` | LIKE注入 | 漏洞路径被触发 |
| LIKE参数绑定 | `GET /sqli/jdbc/special2-Like?type=prepareStatement&keyword=admin' OR '1'='1` | LIKE注入 | 作为普通关键词处理 |
| LIMIT参数 | `GET /sqli/jdbc/special3-Limit?type=prepareStatement&size=1` | 正整数 | 正常返回限制条数 |
| 二次注入-写入 | `GET /sqli/jdbc/special4-SecondOrder?type=store&username=second_order' OR '1'='1&password=demo` | 恶意用户名 | 使用参数化写入成功，不在第一步触发 |
| 二次注入-触发 | `GET /sqli/jdbc/special4-SecondOrder?type=trigger&id=<写入返回ID>` | 已存储恶意用户名 | 第二次查询拼接数据库中的username，返回多条记录或表现出注入效果 |
| 二次注入-安全对照 | `GET /sqli/jdbc/special4-SecondOrder?type=safeTrigger&id=<写入返回ID>` | 已存储恶意用户名 | 使用参数绑定，恶意内容作为普通username查询 |
| UNION回显 | `GET /sqli/jdbc/special5-Union?type=raw&id=-1 UNION SELECT 1,database(),user()` | UNION Payload | 回显当前数据库名和数据库用户 |
| UNION参数绑定 | `GET /sqli/jdbc/special5-Union?type=prepareStatement&id=-1 UNION SELECT 1,database(),user()` | UNION Payload | Payload作为普通参数，不改变SQL结构 |

### MyBatis场景测试

页面：`/sqli/mybatis`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 内置方法 | `POST /sqli/mybatis/safe1?type=select&id=2` | 合法ID | 正常查询 |
| 内置方法缺少ID | `POST /sqli/mybatis/safe1?type=delete` | 缺少ID | 返回`id不能为空!` |
| 自定义`#{}` | `POST /sqli/mybatis/safe2?type=select&id=999999` | 不存在ID | 返回`用户ID不存在!`，不出现空指针 |
| ORDER BY `${}` | `POST /sqli/mybatis/special1-OrderBy?type=raw&field=username and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)%23` | 动态字段注入 | 漏洞路径被触发 |
| ORDER BY `#{}`误区 | `POST /sqli/mybatis/special1-OrderBy?type=prepareStatement&field=username` | 合法字段 | 不能作为真正动态字段排序 |
| ORDER BY白名单 | `POST /sqli/mybatis/special1-OrderBy?type=writeList&field=username` | 合法字段 | 正常返回 |
| LIKE `${}` | `POST /sqli/mybatis/special2-Like?type=raw&keyword=1' OR '1'='1` | LIKE注入 | 漏洞路径被触发 |
| LIKE `#{}` | `POST /sqli/mybatis/special2-Like?type=prepareStatement&keyword=admin' OR '1'='1` | LIKE注入 | 作为普通关键词处理 |
| IN `${}` | `POST /sqli/mybatis/special3-In?type=raw&scope=1) OR 1=1 -- ` | IN注入 | 漏洞路径被触发 |
| IN `#{}`误区 | `POST /sqli/mybatis/special3-In?type=prepareStatement&scope=1,2` | 多ID | 作为单个参数处理，不能展开多个占位 |
| IN foreach | `POST /sqli/mybatis/special3-In?type=Foreach&scope=1,2,abc` | 混入非法值 | 忽略非法值，使用合法整数查询 |
| IN foreach空值 | `POST /sqli/mybatis/special3-In?type=Foreach` | 缺少scope | 返回`scope中没有合法整数ID!` |

### Hibernate与JPA场景测试

页面：`/sqli/hibernate`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| Hibernate原生SQL | `POST /sqli/hibernate/vul1?username=admin' OR 1=1 OR '1'='1` | 注入payload | 返回多条记录或表现出注入效果 |
| Hibernate HQL | `GET /sqli/hibernate/vul2?username=admin' OR 1=1 OR '1'='1` | 注入payload | 返回多条记录或表现出注入效果 |
| Hibernate参数化 | `POST /sqli/hibernate/safe?username=admin' OR 1=1 OR '1'='1` | 注入payload | 当作普通用户名，返回未找到记录 |

页面：`/sqli/jpa`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| JPA JPQL | `GET /sqli/jpa/vul1?username=admin' OR '1'='1` | 注入payload | 返回多条记录或表现出注入效果 |
| JPA动态排序 | `GET /sqli/jpa/vul2?orderBy=username desc` | 动态排序字段 | 正常排序；异常payload应暴露风险 |
| JPA参数化 | `GET /sqli/jpa/safe?username=admin' OR '1'='1` | 注入payload | 当作普通用户名，返回未找到记录 |
| JPA排序白名单 | `GET /sqli/jpa/safe-order?orderBy=username` | 合法字段 | 正常排序 |
| JPA排序白名单拦截 | `GET /sqli/jpa/safe-order?orderBy=username desc` | 非白名单字段 | 返回排序字段不合法 |

## 任意文件操作

当前覆盖任意文件上传、任意文件读取、任意文件下载、任意文件删除四类常见风险，能串联“上传恶意文件 -> 通过静态映射访问 -> 读取/下载敏感文件 -> 删除业务文件”的典型文件安全链路。

任意文件类漏洞的本质是用户可控的文件名、路径、内容或文件元数据进入文件系统操作后，应用没有正确限制目录边界、文件类型、访问方式和业务权限。修复时不要只依赖字符串替换、黑名单或前端限制，应使用后端白名单、服务端生成文件名、路径标准化、真实路径校验、目录隔离、权限校验和审计日志。

已覆盖类型

| 分类     | 已有场景                                        | 结论                                                         |
| -------- | ----------------------------------------------- | ------------------------------------------------------------ |
| 文件上传 | 任意类型上传、图片后缀白名单、图片内容校验      | 覆盖上传入口、后缀校验误区和上传后访问方式的影响             |
| 文件读取 | 绝对路径/目录穿越读取、上传目录限制             | 覆盖敏感文件读取和安全目录边界校验                           |
| 文件下载 | 绝对路径/目录穿越下载、文件名校验、上传目录限制 | 覆盖附件下载类接口的常见风险                                 |
| 文件删除 | 任意路径删除、上传目录限制                      | 覆盖破坏性文件操作风险，并强调只使用临时文件测试             |
| 静态映射 | `/file/**` 映射到上传目录                       | 说明上传文件可被访问，需关注脚本解析、内容类型和独立域名隔离 |

模块覆盖符合综合性靶场定位。后续如需增强，可补充“Zip Slip压缩包目录穿越”“文件覆盖/路径可控文件名”“软链接绕过专项”“MIME/魔数绕过”“大文件/压缩炸弹DoS”“日志文件读取/下载”等场景。当前 XSS 模块已包含 HTML/SVG/PDF/XML 上传导致 XSS 的内容安全案例，任意文件模块保留为文件系统操作主线即可。

### 文件上传测试

页面：`/file/upload`

| 场景                  | 请求/入口                   | 测试输入                             | 预期结果                                           |
| --------------------- | --------------------------- | ------------------------------------ | -------------------------------------------------- |
| 任意文件上传          | `POST /file/upload/vul`     | `test.jsp` 或任意扩展名文件          | 返回“上传文件成功”及 `/file/<文件名>` 访问路径     |
| 上传后访问            | `GET /file/<文件名>`        | 上一步返回文件名                     | 文件可被静态映射访问；Spring Boot 默认不会解析 JSP |
| 安全上传-图片         | `POST /file/upload/safe`    | 真实 `png/jpg/gif/jpeg/bmp/ico` 图片 | 后缀白名单和图片内容校验均通过，上传成功           |
| 安全上传-脚本拦截     | `POST /file/upload/safe`    | `jsp/php/html`                       | 返回“只能上传图片哦！”                             |
| 安全上传-伪造后缀拦截 | `POST /file/upload/safe`    | 内容不是图片的 `test.png`            | 返回“文件内容与图片类型不匹配！”                   |
| 流量包/示例Payload    | 页面右上角 Payload/流量分析 | `test.jsp`、`upload.pcapng`          | 可下载对应测试文件                                 |

### 文件读取测试

页面：`/file/read`

| 场景                  | 请求                                                | 测试输入           | 预期结果                                   |
| --------------------- | --------------------------------------------------- | ------------------ | ------------------------------------------ |
| 绝对路径读取          | `GET /file/read/vul?fileName=/etc/hosts`            | `/etc/hosts`       | 返回文件内容                               |
| 目录穿越读取          | `GET /file/read/vul?fileName=../../../../etc/hosts` | `../` payload      | 如果路径解析到真实文件，返回文件内容       |
| 安全读取-越权拦截     | `GET /file/read/safe?fileName=/etc/hosts`           | 绝对路径           | 返回“访问被拒绝：文件路径不合法”或不可访问 |
| 安全读取-目录内文件   | `GET /file/read/safe?fileName=<上传目录内文件名>`   | 上传目录内普通文件 | 返回文件内容                               |
| 安全读取-符号链接绕过 | `GET /file/read/safe?fileName=<指向外部的软链接>`   | 上传目录内软链接   | 返回“文件真实路径不合法”                   |

### 文件下载测试

页面：`/file/download`

| 场景                  | 请求                                                    | 测试输入           | 预期结果                         |
| --------------------- | ------------------------------------------------------- | ------------------ | -------------------------------- |
| 绝对路径下载          | `GET /file/download/vul?fileName=/etc/passwd`           | `/etc/passwd`      | 以附件形式返回文件，存在则可下载 |
| 目录穿越下载          | `GET /file/download/vul?fileName=../../../../etc/hosts` | `../` payload      | 如果路径解析到真实文件，返回附件 |
| 安全下载-非法文件名   | `GET /file/download/safe?fileName=/etc/hosts`           | 绝对路径           | 返回 400 或 404，不允许下载      |
| 安全下载-目录内文件   | `GET /file/download/safe?fileName=<上传目录内文件名>`   | 上传目录内普通文件 | 正常下载                         |
| 安全下载-符号链接绕过 | `GET /file/download/safe?fileName=<指向外部的软链接>`   | 上传目录内软链接   | 返回 403 “文件真实路径不合法”    |

### 文件删除测试

页面：`/file/delete`

| 场景                  | 请求                                                         | 测试输入           | 预期结果                         |
| --------------------- | ------------------------------------------------------------ | ------------------ | -------------------------------- |
| 任意路径删除          | `GET /file/delete/vul?filePath=./src/main/resources/static/upload/demo.txt` | 临时测试文件       | 文件存在时返回删除成功           |
| 目录穿越删除          | `GET /file/delete/vul?filePath=../../tmp/demo.txt`           | 仅限临时文件       | 如果路径存在且有权限，会尝试删除 |
| 安全删除-越权拦截     | `GET /file/delete/safe?fileName=../test`                     | `../` payload      | 返回“访问被拒绝：文件路径不合法” |
| 安全删除-目录内文件   | `GET /file/delete/safe?fileName=<上传目录内文件名>`          | 上传目录内普通文件 | 文件存在时删除成功               |
| 安全删除-符号链接绕过 | `GET /file/delete/safe?fileName=<指向外部的软链接>`          | 上传目录内软链接   | 返回“文件真实路径不合法”         |



## SSRF

当前覆盖任意协议请求、本地文件读取、内网HTTP访问、跳转链访问内网，以及协议、域名白名单、解析后IP校验和禁止自动跳转等常见修复点。

SSRF的本质是服务端把用户可控的URL、主机名或资源地址用于发起网络请求，且未限制协议、目标主机、解析后的IP和跳转链路。攻击者可借服务端网络身份访问内网服务、云元数据、管理端口、本地文件或第三方资源。修复优先使用业务枚举或服务端映射，不直接接受完整URL；必须限制协议、校验白名单域名、解析所有目标IP并拦截内网地址，且对30x跳转链路逐跳复检。

已覆盖类型

| 分类         | 已有场景                                            | 结论                                              |
| ------------ | --------------------------------------------------- | ------------------------------------------------- |
| 任意协议请求 | `URLConnection`直接请求用户输入URL                  | 覆盖SSRF最基础成因，可演示`file://`和`http://`    |
| 本地文件读取 | `file:///etc/hosts`、`file:///etc/passwd`           | 覆盖服务端本地文件被读取的影响                    |
| 内网HTTP访问 | `http://127.0.0.1/ssrf/internal/metadata`           | 覆盖内网服务/云元数据类风险，使用靶场内置模拟接口 |
| 跳转链风险   | `/ssrf/redirect?target=...`                         | 覆盖只校验第一跳但自动跟随跳转的常见绕过点        |
| 安全写法     | http(s)协议、域名白名单、解析后IP校验、禁用自动跳转 | 覆盖推荐修复主线                                  |

模块覆盖符合综合性靶场定位。后续如需增强，可补充“DNS重绑定演示”“IPv6/十进制/八进制地址绕过对比”“gopher打Redis/MySQL协议利用”“Webhook回调SSRF”“图片/文档解析器触发SSRF”等专项场景。考虑到这些更偏绕过和攻击链扩展，当前模块保留为SSRF基础成因与修复主线即可。

### SSRF漏洞场景测试

页面：`/ssrf`

| 场景           | 请求                                                         | 测试输入              | 预期结果                                             |
| -------------- | ------------------------------------------------------------ | --------------------- | ---------------------------------------------------- |
| 页面访问       | `GET /ssrf`                                                  | 无                    | 页面正常打开，展示漏洞场景、安全场景、tips和代码片段 |
| 本地文件读取   | `GET /ssrf/vul?url=file:///etc/hosts`                        | `file:///etc/hosts`   | 返回本机hosts文件内容                                |
| 内网HTTP访问   | `GET /ssrf/vul?url=http://127.0.0.1/ssrf/internal/metadata`  | 本机内网模拟元数据URL | 返回`instance-id`、`role`、`token`等模拟元数据       |
| 跳转链访问内网 | `GET /ssrf/vul?url=http://127.0.0.1/ssrf/redirect?target=http://127.0.0.1/ssrf/internal/metadata` | 第一跳为跳转接口      | 漏洞请求跟随跳转后返回模拟元数据                     |
| 协议探测       | `GET /ssrf/vul?url=dict://127.0.0.1:6379/info`               | 非HTTP协议            | 返回连接异常或协议处理结果，用于观察任意协议风险     |
| 流量包下载     | 页面流量分析按钮                                             | `ssrf.pcapng`         | 可下载对应流量包                                     |

### SSRF安全场景测试

页面：`/ssrf`

| 场景             | 请求                                                         | 测试输入        | 预期结果                                                     |
| ---------------- | ------------------------------------------------------------ | --------------- | ------------------------------------------------------------ |
| 非HTTP协议拦截   | `GET /ssrf/safe?url=file:///etc/hosts`                       | `file://`       | 返回“检测到不是http(s)协议！”                                |
| 内网地址拦截     | `GET /ssrf/safe?url=http://127.0.0.1/ssrf/internal/metadata` | 回环地址        | 返回“非白名单域名！”                                         |
| 用户信息混淆拦截 | `GET /ssrf/safe?url=http://baidu.com@127.0.0.1/ssrf/internal/metadata` | `userinfo@host` | 返回“非白名单域名！”                                         |
| 白名单域名       | `GET /ssrf/safe?url=http://baidu.com`                        | 白名单域名      | 通过协议和白名单校验，返回远端响应或网络访问结果             |
| 跳转链拦截       | `GET /ssrf/safe?url=http://127.0.0.1/ssrf/redirect?target=http://127.0.0.1/ssrf/internal/metadata` | 跳转到内网      | 第一跳目标不在白名单，直接返回“非白名单域名！”；安全代码同时禁用自动跳转 |
| 超时控制         | 访问慢速或不可达HTTP地址                                     | 慢速目标        | 连接/读取超时后返回异常信息，不长期阻塞请求线程              |


## XXE

当前覆盖XMLReader、SAXParser、DocumentBuilder三类常见Java XML解析入口，可演示外部实体读取本地文件、通过外部实体访问内网地址，以及禁用DOCTYPE/外部实体/外部DTD/外部Schema的修复方式。

XXE的本质是应用解析不可信XML时允许DTD或外部实体，攻击者可通过SYSTEM/PUBLIC外部实体让解析器读取本地文件、访问内网地址、触发SSRF，或利用实体膨胀造成拒绝服务。修复不应依赖某个解析器版本的默认行为，应在每个XML解析入口显式禁用DOCTYPE、外部通用实体、外部参数实体和外部DTD加载；DOM类解析器还应限制`ACCESS_EXTERNAL_DTD`和`ACCESS_EXTERNAL_SCHEMA`。

已覆盖类型

| 分类 | 已有场景 | 结论 |
| --- | --- | --- |
| SAX/XMLReader | `XMLReaderFactory.createXMLReader()` | 覆盖底层SAX解析入口的外部实体展开风险 |
| SAXParser | `SAXParserFactory.newInstance()` | 覆盖常见SAXParser封装场景，强调不要依赖默认安全行为 |
| DOM/DocumentBuilder | `DocumentBuilderFactory.newInstance()` | 覆盖业务中常见DOM解析、配置导入、XML文档读取场景 |
| 安全写法 | 禁用DOCTYPE、外部实体、外部DTD、外部Schema，配置空EntityResolver | 覆盖推荐修复主线 |
| 辅助检测 | 关键词黑名单检测`ENTITY`、`DOCTYPE` | 保留为辅助检测，不作为根因修复 |

模块覆盖符合综合性靶场定位。后续如需增强，可补充“StAX/XMLInputFactory”“JAXB Unmarshaller”“dom4j SAXReader/JDOM SAXBuilder”“XInclude”“Billion Laughs实体膨胀DoS”“盲XXE/OOB回连”等专项场景。当前模块保留为Java常见解析器入口与安全配置主线即可。

### XXE漏洞场景测试

页面：`/xxe/vul`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 页面访问 | `GET /xxe/vul` | 无 | 页面正常打开，展示XMLReader、SAXParser、DocumentBuilder漏洞场景和代码片段 |
| XMLReader读取本地文件 | `GET /xxe/vul1?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | 返回hosts文件内容，证明外部实体被展开 |
| XMLReader访问内网 | `GET /xxe/vul1?payload=<xml>` | `<!ENTITY xxe SYSTEM "http://127.0.0.1/ssrf/internal/metadata">` | 返回模拟元数据，证明可触发SSRF链路 |
| SAXParser读取本地文件 | `GET /xxe/vul2?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | 返回hosts文件内容或解析器外部实体展开结果 |
| DocumentBuilder读取本地文件 | `GET /xxe/vul3?payload=<xml>` | `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | 返回hosts文件内容，证明DOM解析器同样受影响 |
| DocumentBuilder访问内网 | `GET /xxe/vul3?payload=<xml>` | `<!ENTITY xxe SYSTEM "http://127.0.0.1/ssrf/internal/metadata">` | 返回模拟元数据 |
| 审计SINK点 | 页面tips | XMLReader、SAXParser、DocumentBuilder、XMLStreamReader等 | 页面列出常见XML解析入口，便于代码审计 |

### XXE安全场景测试

页面：`/xxe/safe`

| 场景 | 请求 | 测试输入 | 预期结果 |
| --- | --- | --- | --- |
| 页面访问 | `GET /xxe/safe` | 无 | 页面正常打开，展示安全配置和辅助检测场景 |
| XMLReader安全配置 | `GET /xxe/safe1?payload=<xml>` | 带DOCTYPE和外部实体的payload | 返回DOCTYPE被禁止或外部实体无法展开的错误信息，不泄露文件内容 |
| XMLReader正常XML | `GET /xxe/safe1?payload=<root>hello</root>` | 不含DTD的普通XML | 返回`hello` |
| DocumentBuilder安全配置 | `GET /xxe/safe3?payload=<xml>` | 带DOCTYPE和外部实体的payload | 返回DOCTYPE被禁止或外部实体无法展开的错误信息，不泄露文件内容 |
| DocumentBuilder正常XML | `GET /xxe/safe3?payload=<root>hello</root>` | 不含DTD的普通XML | 返回`hello` |
| 黑名单辅助拦截 | `GET /xxe/safe2?payload=<xml>` | 带`DOCTYPE`或`ENTITY`关键字 | 返回`[+]检测到恶意XML！` |
| 黑名单正常XML | `GET /xxe/safe2?payload=<root>hello</root>` | 普通XML | 返回`[-]XML内容安全` |

## 跨源安全

当前覆盖 CORS 配置错误、CORS 白名单修复、JSONP 敏感数据泄露、JSONP callback 校验与公开数据返回四类场景。模块重点演示同源策略约束的是浏览器脚本“读取跨源响应”的能力，服务端一旦错误放宽 CORS 或继续用 JSONP 承载敏感数据，就可能把登录态接口的数据暴露给攻击者站点。

跨源安全问题的本质是跨站点读取边界配置不当。CORS 不是认证或鉴权机制，`Access-Control-Allow-Origin` 只是在告诉浏览器哪些来源可以读取响应；允许凭证时必须精确返回可信 Origin，不能反射任意 Origin 或使用通配策略。JSONP 依赖 `script` 标签跨源加载执行，不适合返回用户身份、权限、订单、Token 等敏感数据；必须保留时只能服务公开只读数据，并严格校验 callback。

已覆盖类型

| 分类          | 已有场景                                                     | 结论                                              |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------- |
| CORS漏洞      | `GET /crossorigin/corsVul` 反射请求 `Origin`，并允许凭证     | 覆盖 CORS 敏感数据跨源读取的典型错误配置          |
| CORS安全写法  | `GET /crossorigin/corsSafe` 精确匹配可信 Origin、限制方法和请求头 | 覆盖白名单、凭证、`Vary: Origin` 等关键修复点     |
| JSONP漏洞     | `GET /crossorigin/jsonpVul?callback=stealData` 返回敏感数据  | 覆盖 JSONP 被任意站点通过 `script` 标签读取的问题 |
| JSONP安全写法 | `GET /crossorigin/jsonpSafe?callback=stealData` 校验 callback，只返回公开数据 | 覆盖 JSONP 保留场景下的最低安全要求               |

模块覆盖符合综合性靶场定位。后续如需增强，可补充“CORS 预检请求专项”“`null` Origin 风险”“正则白名单绕过”“子域信任边界”“postMessage origin 校验”“WebSocket Origin 校验”等场景。当前模块保留 CORS 与 JSONP 两条主线即可，postMessage 已在 XSS HTML5 场景中覆盖，避免重复堆叠。

### CORS漏洞场景测试

页面：`/crossorigin/cors`

| 场景             | 请求                           | 测试输入                             | 预期结果                                                     |
| ---------------- | ------------------------------ | ------------------------------------ | ------------------------------------------------------------ |
| 页面访问         | `GET /crossorigin/cors`        | 已登录会话                           | 页面正常打开，展示 CORS 漏洞、白名单修复和代码片段           |
| 无Origin直接访问 | `GET /crossorigin/corsVul`     | 不带 `Origin`                        | 返回敏感演示数据，响应带默认 `Access-Control-Allow-Origin: http://example.com` |
| 反射任意Origin   | `GET /crossorigin/corsVul`     | Header `Origin: http://evil.example` | 返回敏感演示数据，响应 `Access-Control-Allow-Origin` 反射为恶意来源 |
| 允许凭证         | `GET /crossorigin/corsVul`     | Header `Origin: http://evil.example` | 响应包含 `Access-Control-Allow-Credentials: true`，说明跨源脚本可在带凭证时读取响应 |
| 预检请求         | `OPTIONS /crossorigin/corsVul` | Header `Origin: http://evil.example` | 返回允许方法和请求头，用于演示过宽预检策略                   |

### CORS安全场景测试

页面：`/crossorigin/cors`

| 场景           | 请求                            | 测试输入                               | 预期结果                                                     |
| -------------- | ------------------------------- | -------------------------------------- | ------------------------------------------------------------ |
| 同源访问       | `GET /crossorigin/corsSafe`     | 不带 `Origin`                          | 返回“同源请求不需要CORS响应头”，不暴露跨源读取策略           |
| 非白名单Origin | `GET /crossorigin/corsSafe`     | Header `Origin: http://evil.example`   | 返回 403 或被 CORS 过滤器拒绝，不返回可信 `Access-Control-Allow-Origin` |
| 白名单Origin   | `GET /crossorigin/corsSafe`     | Header `Origin: http://127.0.0.1:8080` | 返回成功，响应 `Access-Control-Allow-Origin: http://127.0.0.1:8080` |
| 白名单预检     | `OPTIONS /crossorigin/corsSafe` | Header `Origin: http://127.0.0.1:8080` | 返回允许 `GET, OPTIONS` 和必要请求头                         |

### JSONP漏洞场景测试

页面：`/crossorigin/jsonp`

| 场景           | 请求                                           | 测试输入             | 预期结果                                                     |
| -------------- | ---------------------------------------------- | -------------------- | ------------------------------------------------------------ |
| 页面访问       | `GET /crossorigin/jsonp`                       | 已登录会话           | 页面正常打开，展示 JSONP 劫持、安全写法和代码片段            |
| JSONP敏感数据  | `GET /crossorigin/jsonpVul?callback=stealData` | `callback=stealData` | 返回 `stealData({"username":"admin","password":"Admin123"});` |
| callback未校验 | `GET /crossorigin/jsonpVul?callback=alert`     | `callback=alert`     | 返回可执行脚本格式，说明任意回调名可控                       |

### JSONP安全场景测试

页面：`/crossorigin/jsonp`

| 场景             | 请求                                                | 测试输入           | 预期结果                                                     |
| ---------------- | --------------------------------------------------- | ------------------ | ------------------------------------------------------------ |
| 合法callback     | `GET /crossorigin/jsonpSafe?callback=stealData`     | 合法函数名         | 返回 `stealData({"message":"public data only"});`，不包含敏感账号密码 |
| 命名空间callback | `GET /crossorigin/jsonpSafe?callback=app.stealData` | 合法命名空间函数名 | 返回 `app.stealData({"message":"public data only"});`        |
| 非法callback     | `GET /crossorigin/jsonpSafe?callback=alert(1)`      | 含括号的非法函数名 | 返回 400 和 `Invalid callback`                               |
| 响应头           | `GET /crossorigin/jsonpSafe?callback=stealData`     | 合法函数名         | 响应 `Content-Type` 为 JavaScript，并带 `X-Content-Type-Options: nosniff` |

## 

# Java 专题
