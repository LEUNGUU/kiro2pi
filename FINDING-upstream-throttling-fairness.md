# 发现:上游限流(429)下缺乏请求隔离 → 批量客户端被交互式会话饿死

> 记录者:外部集成方(Yap 自托管编译引擎)。2026-06-01 端到端联调时定位。
> 这不是 bug 报告,是一次真实多客户端争用的现场分析 + 改进建议。kiro2pi 本身行为正确。

## 现象

Yap(一个走 `/v1/chat/completions` 的自托管文章编译引擎)在与一个交互式 Pi 会话(Node 客户端)**同时**使用同一个 kiro2pi 实例(localhost:9090)时,Yap 的编译请求反复 `ReadTimeout`、最终饿死失败;而该交互式会话正常。Yap 单独跑(无其他负载)时 100% 成功。

## 根因(已用日志证实)

不是 kiro2pi 的本地并发问题(确认:`http.Server` 每请求一个 goroutine,并发处理;`tokenMutex` 只是 token 缓存的短临界区,非请求级锁)。

真因在**上游**:两个客户端共享同一个 Kiro/CodeWhisperer 账号,高强度交互会话触发**账号级 429 限流**。`~/Library/Logs/kiro2pi.log.0` 尾部 5000 行证据:

```
 94  429
  6  ThrottlingException
 20  rateLimit
~1100  retry / Retry
```

因果链:
1. 交互式会话高频打 kiro2pi(实测 ~1548 日志行 / 5s)。
2. 上游 CodeWhisperer 返回 429 Throttling。
3. kiro2pi 对 429 指数退避重试(`retryBaseDelay=1s`,1→2→4s),**但所有请求平等地抢同一个被限流的配额,没有公平调度或客户端隔离**。
4. 批量客户端(Yap)的请求同样吃 429;kiro2pi 还在退避期间没吐任何字节,Yap 侧的流式 read 超时(30s)先放弃 → 整条编译链饿死。

即:**上游限流 + kiro2pi 无请求间公平性/隔离,导致重负载客户端把轻负载客户端挤死。**

## 改进建议(按性价比排序,均为最小改动)

1. **上游 HTTP client 设超时(防线程泄漏)** — `handleStreamRequest` / line 3011/3074/3367 的 `client := &http.Client{}` 无 `Timeout`,零值是无限等待。上游若挂死,goroutine 永不回收。建议设 `&http.Client{Timeout: 120 * time.Second}`(或按需调)。这是独立于本问题的健壮性缺陷。

2. **暴露 429 给客户端,而不是无限本地退避** — 当上游持续 429 且重试预算耗尽时,直接把 `429 Too Many Requests` + `Retry-After` 头透传给调用方,让客户端自己决定退避,而不是在 kiro2pi 内部默默 backoff 到调用方超时。这样 Yap 能收到明确的 429(可重试)而非模糊的 ReadTimeout。

3. **并发上限 + 排队(公平性)** — 加一个带缓冲的信号量(如 `maxConcurrentUpstream = 4`)限制同时打上游的请求数;超出则排队。配合短排队超时,避免单个客户端用并发请求独占配额。可选:按客户端标识(如 header / API key)做加权公平队列,让批量任务不饿死交互会话,反之亦然。

4. **可观测:per-client 指标** — 已有 `observability.db`;增加按客户端来源(User-Agent / 自定义 header)统计 429 率与延迟,便于诊断"谁在打满配额"。

## 对集成方(Yap)的启示

架构上 Yap 计划在生产用**独占的 LLM endpoint**(独立 EC2 上的 kiro2pi),不与交互式会话共享账号/配额——届时本问题自然消失。本地联调时共享 kiro2pi 才暴露了它。建议 1(client 超时)无论是否多租户都值得修。
