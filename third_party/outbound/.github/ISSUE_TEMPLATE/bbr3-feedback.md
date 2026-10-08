---
name: bbr3 测试反馈
about: 反馈实验性 bbr3 拥塞控制的启用、对照测试或回退结果
title: '[bbr3] '
labels: ''
assignees: ''
---

<!--
感谢测试 bbr3。它是一个实验性、opt-in、非默认的自制拥塞控制器。
在提交之前，请先阅读 docs/bbr3-experimental.md 的"当前证据等级"与"已知限制"。
证据不足的反馈（缺少 dae/fork 提交、缺少场景与对比对象）会被要求补充。
请勿在标题里去掉 [bbr3] 前缀。
-->

## 环境

- **dae 版本 / 提交**：
- **outbound fork 提交**（分支 + sha + 伪版本，例如 `feat/bbr3-experimental @ <sha> = v0.0.0-...`）：
- **服务端软件与版本**（如 sing-box / tuic-server，版本号）：
- **服务端是否做过改动**（默认应为"未改动"，服务端无需支持 bbr3）：
- **内核 / 发行版 / 架构**：

## 客户端链路配置（脱敏）

- **协议**：tuic / juicity / hysteria2

```text
tuic://***:***@<server>:<port>?congestion_control=...&cc_override=...&cwnd=...
juicity://***:***@<server>:<port>?congestion_control=...&cc_override=...&cwnd=...
hysteria2://***:***@<server>:443?upmbps=...&downmbps=...&cc_override=...
```

- uuid / 密码 / 域名 / IP 请用 `***` 代替。
- 请保留 `cc_override` 与带宽参数（`cwnd` / `upmbps` / `maxTx`）的原值。

## 场景

- **链路**：接入带宽 / 瓶颈带宽 / 单向时延 / 抖动 / 丢包模型（或写"真实公网"）/ 队列大小
- **是否单流**：是 / 否（若否，请说明并发流数量与类型）
- **时长 / 轮次**：每臂 n=？
- **对比对象**：原版 bbr / cubic / brutal / bbr2 / 其它（写清版本或提交）
- **测试方式**（命令、脚本、iperf/curl/自研工具）：

## 结果（逐臂列出）

| 指标 | bbr3 臂 | 对比臂 | 说明 |
|---|---|---|---|
| goodput (Mbps，均值/中位，样本数) | | | |
| p50 延迟 (ms) | | | |
| p95 延迟 (ms) | | | |
| p99 延迟 (ms) | | | |
| 测量点（应用层 / 内核 / 线缆） | | | |
| 队列丢包 / 重传 | | | |
| CPU 占用（客户端/服务端，核数或百分比） | | | |

## 连接异常

- 有无 panic / 连接重置 / 超时 / 断流：有 / 无
- 若有，请贴日志片段：

## 结论

- 相对对比对象：更好 / 相当 / 更差（goodput、p95 分别写）
- 是否复现 docs/bbr3-experimental.md §2.1 的 p95 优势（−39% / −44%）：
- 是否命中"会推翻当前结论"的任一情形（§8）：
- 你认为可能影响结论的因素：

## 回退状态

- 是否已回退：是 / 否
- 回退方式：① 改链接（去掉 `cc_override` 或改为 `bbr`）/ ② 切分支或 revert / ③ dae go.mod 钉回旧提交
- 回退后是否恢复正常：
