# 常规漏洞

## 跨站脚本



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
