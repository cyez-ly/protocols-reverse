# 示例目录说明

本目录用于放置抓包样例与触发器输入示例，方便本地调用。

## 文件用途

- `*.pcap / *.pcapng`：协议逆向输入样例。
- `flow_input.json`：触发器接口的 JSON 负载示例（对应 [run_with_trigger](/root/crewAI/testcrewai/src/testcrewai/main.py:127) 的参数结构）。

## `flow_input.json` 是什么

`flow_input.json` 用于“以 JSON 方式触发流程”时传参，核心字段包括：

- `pcap`：输入抓包路径
- `output`：输出目录
- `python_bin`：全局兜底 Python 解释器
- `netzob_python_bin` / `nemesys_python_bin` / `netplier_python_bin` / `binaryinferno_python_bin`：各工具独立解释器
- `timeout`：子进程超时秒数
- `use_llm`：是否启用 LLM 的api调用

注意：平时直接用 **cli** 运行时，不依赖这个文件；cli 用的是 `python app/main.py --pcap ... --output ...`。

## 运行示例

```bash
python app/main.py --pcap examples/dhcp_100.pcap --output outputs/run_demo
```

## 样本覆盖

- 常见协议：`HTTP`、`DNS`、`TLS`、`ICMP`、`DHCP`、`NTP`、`SMB`
- 工业协议：`DNP3`、`Modbus`、`S7`、`BACnet`、`OPC UA`

## 扩展功能

- 一些公开抓包文件后缀可能是 `.pcap`，实际格式却是 `pcapng`（或者相反）。
- 本项目预处理阶段会优先按文件头判断格式，因此后缀不一致也能处理。
