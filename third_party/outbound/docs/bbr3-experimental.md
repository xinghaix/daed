# bbr3 实验性拥塞控制：启用、回退与反馈指南

> 状态：**实验性、默认启用（2026-09-09 起）**。本文面向所有用户与测试者。
> 接入代码：`protocol/tuic/congestion/bbr3/`（自制实现）+ `cc_override` 本地覆盖开关。
> 行为契约：不设置 `cc_override` 时，TUIC / Juicity / Hysteria2 客户端默认安装 bbr3
> （Hysteria2 会把 min(serverRx, clientTx) 作为 hint 传入；TUIC/Juicity 不传 hint）。
> 显式参数仍然优先：`cc_override=bbr` 可恢复此前的稳定默认。

---

## 1. 这是什么

`bbr3` 是本仓库自带的一个**自制（homemade）拥塞控制器**，放在
`protocol/tuic/congestion/bbr3/`，通过 `cc_override` 在 **TUIC / Juicity / Hysteria2**
三个 QUIC 协议的客户端侧 opt-in 使用。

- 名字是历史命名：**它不是 BBRv3 的参考实现，也没有做过 BBRv3 一致性验证**。
  Linux 内核版本、gain 常量、PROBE_RTT 目标这类"看起来像 BBRv3"的特征都不能作为
  一致性或规格符合性的证据（见 `protocol/tuic/congestion/bbr3/doc.go`）。
- 它使用简化的 ACK 采样、round 滤波、模式循环、自适应丢包阈值和 inflight 边界，
  行为与参考 BBR 实现存在差异；没有完整的 ECN/恢复模型、Reno 共存逻辑、
  ACK 聚合补偿或随机化探测调度。
- ~~默认**不会被选中**：只有通过下面的 `cc_override` 才会生效。~~
  **2026-09-09 起默认启用**：不设置 `cc_override` 的 TUIC/Juicity/Hysteria2 链接
  也会安装 bbr3；`cc_override=bbr` 可退回稳定默认（见 §3）。
- 接入面：`cc_override` 覆盖 `tuic`、`juicity`、`hysteria2`；`naive` 的 QUIC 模式未接入
  （dialer 直接返回 "not supported yet"）。
- 可选的 `hint`（接入带宽上限）默认只作为**上限**，不是目标速率；
  其"验证授权"门控（`EnableValidatedHint`）默认关闭，且**不推荐开启**（见 §2.3）。

---

## 2. 当前证据等级（先读这一节再决定要不要测）

### 2.1 只有用户态仿真证据

现有全部结论来自 `ccbench` 用户态链路仿真（应用层时间戳模拟、单流、固定 40ms 单向时延、
256KB FIFO、确定性丢包模型、单次运行 ≤40s）。**没有**真实公网、竞争流/公平性、
长时间运行、多连接/多包长、异步路由变化等证据。

冻结产物：`/root/ccbench/audit/paired-20260909-final`（每配置 n=5 次运行，取各运行值的均值）。

| 场景 | 控制器 | goodput (Mbps) | p95 (ms) | p99 (ms) | 相对原版 BBR |
|---|---|---|---|---|---|
| accurate | 原版 BBR | 18.801 | 167.89 | 168.34 | 基准 |
| accurate | **bbr3**（hint=20Mbps，默认参数） | **18.921** | **102.33** | 107.56 | goodput +0.6%，**p95 −39%** |
| loss5（5% 丢包） | 原版 BBR | 17.419 | 332.86 | 349.12 | 基准 |
| loss5（5% 丢包） | **bbr3**（hint=20Mbps，默认参数） | **17.625** | **185.19** | 212.14 | goodput +1.2%，**p95 −44%** |
| accurate | sing-quic bbr2（适配版） | 19.183 | 166.21 | 166.45 | bbr3 在 accurate **吞吐输给 bbr2**（18.92 vs 19.18） |

必须同时知道的事实：

- **吞吐收益极小**（+0.6% / +1.2%），在 n=5 的方差下**不能**认定吞吐更优；
  证据支持的主要是**延迟分布改善**。
- **在 accurate 场景，bbr3 的吞吐低于适配的 sing-quic bbr2**（18.92 vs 19.18 Mbps）。
  （附注：同一批产物中 loss5 场景下适配 bbr2 塌到 3.22 Mbps / p95 1070ms；这属于
  对照实现的行为，**不得**作为"bbr3 优于 bbr2"的结论——适配外部实现没有等价性认证。）
- **无竞争流 / 无公平性证据**：所有运行都是单流独占瓶颈。
- 独立评审（`/root/ccbench/audit/FINAL_REVIEW.md`）的结论是：
  没有已证明的性能收益、没有 BBRv3 一致性声明、**不建议 rollout**；
  所有主实验的 hint 验证次数为 0；n=5 的统计假设较弱；
  测量是应用层时间戳模拟而非线缆测量。

### 2.2 何时可以考虑试用

适合：单流、可复现的对照测试，想验证 p95 延迟优势是否在真实链路复现。

不适合：生产默认开启、把 bbr3 当作 bbr2/cubic 的替代、任何"必须更优"的假设。

### 2.3 hint 门控已被诊断证明惰性

`bbr3` 的 `hint`（由链接的 `cwnd` 字段传入）默认只当上限。
"验证后临时授权目标速率"的实验门控经诊断（`/root/ccbench/audit/diag-20260910/DIAG.md`）
证明：

- H1 **证实**：accurate 场景的拒绝 100% 来自 RTT 界（9512/9512），门凑不满连续 clean 窗口；
- H2 **证实**：13 个 run 的 `lift_events` 全为 0，结构上授权幅度 ≤ ~10%；
- H3 **证实**：深跌后 probe/validation 都无法启动，无法加速恢复。

因此：`EnableValidatedHint` **默认 false 保持不变，且不推荐开启**。开启它不会带来
已证明的收益，只会引入未被验证的行为分支。

---

## 3. 如何启用

`cc_override` 是**客户端本地**参数，三个协议语义一致，按各自链接风格追加即可：

| 项 | 说明 |
|---|---|
| `cc_override` | **只在客户端本地生效，不发给服务端**。服务端回显/下发的 CC 都会被本地覆盖。 |
| 白名单 | `bbr`、`cubic`、`new_reno`、`brutal`、`bbr3`。非法值在构造 dialer 时**直接报错**（fail fast），不会静默回退成 BBR。 |
| 大小写/空白 | 解析时统一转小写并去空白：`cc_override=BBR3`、`cc_override=%20bbr3%20` 等价于 `cc_override=bbr3`。 |
| 服务端 | 三个协议都**不需要**服务端支持或改动。 |

> 注意：白名单里的 `cubic`/`new_reno` 目前**没有本地实现**。tuic / juicity 会把它们落到 BBR
> （与接入前服务端回显 `cubic` 的行为一致）；hysteria2 则在构造 dialer 时直接报错。
> 需要确定性 BBR 时请显式写 `cc_override=bbr`。

### 3.1 TUIC

```text
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3
```

- `congestion_control` 仍按原逻辑发给服务端并回显（`Feature1` 不变）；服务端**无需支持 bbr3**，写 `bbr`/`cubic`/留空都可以。
- `cwnd` 对 bbr3 是**接入带宽上限（字节/秒）**，只作上限、不是目标；`0`/不设 = 不设上限、纯探测。
- **复现 §2.1 实验配置**：实验里的 bbr3 臂使用 `hint = 20 Mbps = 2,500,000 字节/秒`、默认参数
  （`EnableValidatedHint=false`、`StrictHintCap=false`）。所以对照测试请显式给出 `cwnd`：

```text
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3&cwnd=2500000
```

`cwnd` 与 brutal 使用同一单位（字节/秒），换算：`字节/秒 = 接入带宽 Mbps × 1e6 / 8`。
不设 `cwnd` 时 bbr3 纯探测，**不在上表证据覆盖范围内**。

### 3.2 Juicity

```text
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr3&cwnd=2500000
```

与 tuic 完全同形：`congestion_control` 仍发给服务端，`cc_override` 只在本地生效，
`cwnd` 是 bbr3 的上限 hint（brutal 语义同 tuic）。tuic 与 juicity 共用同一份白名单与
fail-fast 语义（`protocol/tuic/common.SelectCongestionController`）。

### 3.3 Hysteria2

```text
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr3
```

- hysteria2 没有 `cwnd` 参数：bbr3 的 **hint = `BandwidthConfig.MaxTx`**，即 `upmbps`
  （或 legacy `maxTx`）换算出的字节/秒；`0` = 纯探测。换算同上（`字节/秒 = Mbps × 1e6 / 8`）。
- `cc_override` **优先于服务端**：即使服务端返回 `RxAuto`（要求客户端做带宽探测），
  也会安装 bbr3 而不是 BBR。
- hy2 支持 `bbr`、`brutal`、`bbr3`；`cubic`/`new_reno` 在白名单内但 hy2 无实现，
  构造 dialer 时**直接报错**，不静默降级。
- `brutal` 保持接入前语义：`min(serverRx, clientTx)`，无带宽时回退 BBR。

### 3.4 不支持：naive+quic

`naive` 的 QUIC 模式 dialer 直接返回 "not supported yet"，`cc_override` 对它无效。

### 3.5 如何确认 bbr3 真的装上了

`dae validate` **不解析节点链接**（连非法端口都会放行），所以不能靠它验证。运行时把日志级别调到
`debug`（`global { log_level: debug }`），tuic / juicity 的每条连接安装控制器时会输出一行：

```text
level=debug msg="installing experimental bbr3 congestion controller" cc=bbr3 hint_bps=2500000
```

看不到这行 = 没生效（链接写错、`cc_override` 拼写错误、或走了其他节点）。
hysteria2 走的是另一条安装路径（握手时按服务端响应分派），**没有这条日志**；对它请用
`cc_override=bbr4` 之类的非法值确认 fail-fast 路径（构造 dialer 即报错），再以延迟分布变化判断。

注意：非法 `cc_override` 在**构造 dialer 时**报错（dae 的 `validate` 不解析链接，
因此不会在配置校验阶段暴露），表现为该节点不可用/连接失败。

---

## 4. 如何回退（三级，任选）

### ① 链接级：立即生效，无需重编译（首选）

- 去掉 `cc_override=bbr3` → 立刻回到服务端回显/下发的控制器；
- 或改成 `cc_override=bbr` → 本地强制 BBR，忽略服务端。

三个协议各自示例：

```text
# TUIC：回退到服务端回显
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr

# TUIC：本地强制 BBR
tuic://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr

# Juicity：回退到服务端回显 / 本地强制 BBR
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr
juicity://<uuid>:<password>@<server>:<port>?congestion_control=bbr&cc_override=bbr

# Hysteria2：回退到服务端驱动（RxAuto→BBR / 带宽→brutal）
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100
# Hysteria2：本地强制 BBR
hysteria2://<auth>:<password>@<server>:443?upmbps=20&downmbps=100&cc_override=bbr
```

改完重载 dae 配置（或重启 dae 进程）即可，**不需要重新编译**。
注意：非法值（例如 `cc_override=bbr4`）会让 dialer 构造失败并报错，不会静默降级——
这是刻意设计，避免拼写错误被掩盖。hysteria2 同理：`cubic`/`new_reno` 也会在构造时被拒绝。

### ② 代码级：撤销合并提交（特性已合入基线）

本特性已以**合并提交**合入基线 `perf/complete-optimizations`：合并提交 `319c8e6`，
两个父提交为 `7a32a56`（基线）与 `934b37c`（特性分支）。回退即撤销该合并：

```bash
cd /root/olicesx-outbound
HOME=/root git revert -m 1 319c8e6     # 保留历史，不重写
```

特性分支 `feat/bbr3-experimental` 仍保留，需要时可重新合并。撤销后若 dae 用本地
`replace` 指向本仓库，重新构建 dae 即可：

```bash
cd /root/dae
HOME=/root go build -tags=$(cat .build_tags) -o dae .
```

### ③ 产品侧：把 dae 的 go.mod replace 钉回旧提交

dae 的基线分支（`kdae`）已钉到合并后的 outbound 提交
`github.com/olicesx/outbound v0.0.0-sticky-ip.0.20260909102757-319c8e694f48`
（即 fork `perf/complete-optimizations` 的合并提交 `319c8e6`）。回退即恢复接入前的旧钉法
（`v0.0.0-sticky-ip.0.20260907140516-07427f11deb3` = fork `07427f1`）：

```bash
cd /root/dae
HOME=/root go mod edit -replace github.com/daeuniverse/outbound=github.com/olicesx/outbound@v0.0.0-sticky-ip.0.20260907140516-07427f11deb3
HOME=/root go mod edit -require github.com/daeuniverse/outbound@v0.0.0-sticky-ip.0.20260907140516-07427f11deb3
HOME=/root go mod tidy
HOME=/root go build -tags=$(cat .build_tags) -o dae .
```

若日后 outbound 基线又有新提交，用下面的命令重新解析伪版本：

```bash
cd /root/dae
HOME=/root GOFLAGS=-mod=mod GOPROXY=direct GOSUMDB=off GOPRIVATE='github.com/olicesx/*' \
  go list -m -json github.com/olicesx/outbound@perf/complete-optimizations
```

语义：三级回退互相独立。① 只改链接（对三个协议都立即生效）；② 只改本地仓库；
③ 只改产品依赖钉法。任意一级都可以单独把 bbr3 从实际链路里移除。

---

## 5. 默认值声明

**不设置 `cc_override` 时，行为与接入前完全一致**（tuic / juicity / hysteria2 三个协议）：

- `header.Feature1`（服务端回显的 CC）仍被原样使用，选择逻辑在 override 为空时
  逐字返回服务端值；
- hysteria2 的空 override 走 `resolveCongestion`，逐字复现原决策：
  `RxAuto → BBR`；否则 `actualTx = min(serverRx, clientTx)`，`>0 → brutal(actualTx)`，
  否则 `BBR`；
- bbr3 不可能被选中（没有任何默认路径指向它）；
- `bbr3.DefaultParams()` 未改动，`EnableValidatedHint` 仍为 false；
- 产品默认值（dae 配置默认、`congestion_control` 默认、`cwnd`/`upmbps`/`maxTx` 语义）全部未改；
- 新增字段 `protocol.Header.CongestionOverride` 只被 tuic / juicity / hysteria2 的 dialer 读取，
  其他协议不受影响（所有 `protocol.Header` 构造均为具名字段）。

---

## 6. 测试要报什么（可复制模板）

把下面整块复制到 issue 或反馈里，能填多少填多少，缺项写"未知"：

```markdown
### 环境
- dae 版本 / 提交：
- outbound fork 提交（分支 + sha + 伪版本，例如 feat/bbr3-experimental @ <sha> = v0.0.0-...）：
- 服务端软件与版本（如 sing-box / tuic-server，版本号）：
- 服务端是否做任何改动（默认：未改动，服务端无需支持 bbr3）：
- 内核 / 发行版 / 架构：
- 协议：tuic / juicity / hysteria2
- 客户端配置（脱敏后）：
  `tuic://***:***@<server>:<port>?congestion_control=...&cc_override=...&cwnd=...`
  `juicity://***:***@<server>:<port>?congestion_control=...&cc_override=...&cwnd=...`
  `hysteria2://***:***@<server>:443?upmbps=...&downmbps=...&cc_override=...`
  （脱敏：uuid、密码、域名、IP 用 `***` 代替；请保留 `cc_override` 与带宽参数原值）

### 场景
- 链路：接入带宽 / 瓶颈带宽 / 单向时延 / 抖动 / 丢包模型（或"真实公网"）/ 队列大小
- 是否单流：是 / 否（若否，说明并发流数量与类型）
- 时长 / 轮次（每臂 n=？）：
- 对比对象：原版 bbr / cubic / brutal / bbr2 / 其它（写清版本或提交）
- 测试方式（命令、脚本、iperf/curl/自研）：

### 结果（逐臂列出）
- goodput（Mbps，均值/中位，注明样本数）：
- 延迟 p50 / p95 / p99（ms，注明测量点：应用层 / 内核 / 线缆）：
- 队列丢包 / 重传（次数或百分比）：
- CPU 占用（客户端 / 服务端，核数或百分比）：
- 连接异常：有无 panic / 连接重置 / 超时 / 断流（贴日志片段）

### 结论与不确定点
- bbr3 相对对比对象：更好 / 相当 / 更差（按 goodput、p95 分别写）
- 是否复现 §2.1 的 p95 优势：
- 你认为哪些因素可能影响结论：
```

---

## 7. 已知限制

- **实现来源**：自制，非参考实现，未做 BBRv3 一致性验证。
- **测量方式**：ccbench 是用户态仿真，应用层时间戳模拟，不是线缆测量。
- **统计强度**：n=5/配置，<1s 量级的差异不可据此排序。
- **场景覆盖**：单流、固定 40ms 时延、256KB FIFO、确定性丢包、≤40s、固定 1200 字节报文。
  未覆盖：真实公网、竞争流与公平性、ACK 频率/聚合影响、多连接与 PMTU、长时间尺度。
- **算法缺口**：自适应丢包基线可能吸收持续拥塞；无完整 ECN/恢复模型；
  无 Reno 共存逻辑；无 ACK 聚合补偿；无随机化探测调度。
- **协议覆盖**：`cc_override` 已接入 `tuic`、`juicity`、`hysteria2`；
  `naive` 的 QUIC 模式未接入（dialer 直接返回 "not supported yet"）。
- **hysteria2 特有限制**：不支持 `cubic`/`new_reno`（构造 dialer 时拒绝）；
  `cc_override` 会覆盖服务端的 `RxAuto`；bbr3 的 hint 只能来自 `upmbps`/`maxTx`
  （没有 `cwnd`）；且 hy2 安装路径不打 debug 日志（§3.5）。
- **证据适用范围**：§2.1 的对照数据来自 ccbench 单流仿真（控制器本体与协议无关），
  juicity / hysteria2 的接入路径、hint 取值与 fail-fast 语义**只有单测证据**，
  没有端到端或性能对照证据。
- **hint 门控**：默认关闭且已证明惰性（§2.3），不推荐开启。
- **回退面**：① 链接级可秒级回退（三个协议通用）；② ③ 需要重建 dae。

## 8. 什么结果会推翻当前结论（falsifier）

出现任意一条，就应当**下调甚至撤回** §2.1 的结论：

1. **高丢包或竞争流下明显劣于 bbr**：在 ≥5% 丢包或存在竞争流时，
   bbr3 的 goodput 显著低于原版 bbr，或 p95/p99 显著更高。
2. **p95 优势不复现**：配对运行（同场景、同 seed 集合、每臂 n≥5）中
   p95 差值置信区间跨 0，或优势方向反转。
3. **真实公网/长时运行退化**：>10 分钟运行出现吞吐持续下滑、恢复变慢、
   或连接异常（重置、超时、断流、panic）。
4. **公平性失败**：与 cubic/bbr 共存时抢占带宽或饿死对方（需专门设计共存实验）。
5. **资源开销**：CPU 或内存占用显著高于 bbr/cubic，或在同等负载下成为瓶颈。
6. **正确性缺陷**：出现 `bbr3` 相关的 panic、负 cwnd/pacing、窗口越界，
   或 ccbench 不变量测试（`/root/ccbench/invariants_test.go`）失败。

反向证据同样重要：如果上述 1–6 在多场景、多轮次、独立复现中都不出现，
且 p95 优势稳定复现，才谈得上把证据等级从"用户态仿真"往上提。
