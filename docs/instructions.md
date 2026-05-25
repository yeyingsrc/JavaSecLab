# 常规漏洞

## 跨站脚本
跨站脚本模块适合作为综合性Java靶场的核心模块：当前覆盖了反射型、存储型、DOM型、模板引擎不安全渲染、文件上传导致的存储型XSS、第三方组件XSS、WebSocket XSS、postMessage XSS、CSP、HttpOnly、输出编码等常见场景。

本次已将页面描述统一为：XSS的本质是不可信数据进入浏览器页面执行上下文后，被当作HTML、脚本、URL或可执行DOM操作解析。修复优先按输出上下文处理数据，普通文本使用HTML实体编码或安全DOM API，URL/属性/JavaScript/CSS等位置使用对应编码与白名单校验；CSP、HttpOnly、输入过滤是辅助防护，不能替代根因修复。

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



## SQL注入

SQL注入模块适合作为综合性Java靶场的核心模块：当前覆盖了JDBC原生拼接、伪预编译拼接、JdbcTemplate拼接、参数化查询、MyBatis动态SQL、Hibernate HQL/原生SQL、JPA JPQL/动态排序等常见开发栈。

本次已将页面描述统一为：SQL注入的本质是不可信输入进入SQL语法结构并改变原SQL语义；修复优先使用参数化查询，列名、表名、排序方向等SQL结构必须使用枚举或白名单映射。黑名单、类型校验、ESAPI编码只作为辅助方案，不应作为首选修复方案。

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


# Java 专题
