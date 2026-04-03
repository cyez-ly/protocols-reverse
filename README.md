# 基于多智能体协同的未知网络协议结构逆向推断系统（CrewAI 原型）

本项目在 CrewAI 官方模板基础上重构，实现了一个可运行的本科毕设原型：

- 输入未知协议流量文件（优先 `.pcap/.pcapng`）
- 自动完成预处理、工具选择、多工具协同分析、结果融合
- 输出结构化 JSON 中间结果与最终 Markdown 报告

该版本强调：**可运行、可解释、模块清晰、便于后续扩展**。

## 1. 总体架构

采用 **Flow + Agents + Tools** 分层：

- `Flow`（`ProtocolReverseFlow`）
  - 主流程编排
  - 步骤日志
  - 失败容错与降级
- `Agents`（CrewAI）
  - `PreprocessAgent`
  - `ToolSelectorAgent`
  - `SegmentationAgent`
  - `SemanticInferenceAgent`
- `FusionAgent`
- `ReportAgent`
- 当前原型中，核心决策优先由本地规则完成，LLM 作为可选注释增强（`--use-llm`）
- `Tools`（统一 subprocess 适配）
  - `ShellRunner`
  - `TsharkTool`
  - `NetzobTool`（优先官方 Netzob API，失败自动降级）
  - `NemesysTool`（优先官方 NEMESYS API，失败自动降级）
  - `NetPlierAdapter`（优先官方 NetPlier `main.py`，失败自动降级）
  - `BinaryInfernoAdapter`（优先官方 BinaryInferno `blackboard.py`，失败自动降级）

## 2. 项目结构

```text
app/
  main.py                          # CLI 启动入口（python app/main.py ...）

src/testcrewai/
  config/
    agents.yaml                    # 6 个智能体配置
    tasks.yaml                     # 6 个任务配置
  adapters/
    netzob_cli.py                  # Netzob 适配器：official API + heuristic fallback
    nemesys_cli.py                 # NEMESYS 适配器：official API + heuristic fallback
    netplier_official_runner.py    # NetPlier 官方兼容启动器（ARP/VLAN 兼容）
    netplier_cli.py                # NetPlier 风格语义 fallback 适配器
    binaryinferno_cli.py           # BinaryInferno 语义 fallback 适配器
    common.py
  tools/
    shell_runner.py                # 统一命令执行层
    protocol_tools.py              # Tshark/Netzob/NetPlier/BinaryInferno 封装
  pipeline/
    preprocess.py                  # 预处理阶段
    tool_selection.py              # 工具选择阶段
    segmentation.py                # 字段切分阶段
    semantics.py                   # 语义推断阶段
    fusion.py                      # 结果融合阶段
    report.py                      # 报告生成阶段
  workflows/
    protocol_reverse_flow.py       # CrewAI Flow 主流程
  crew.py                          # @CrewBase crew 定义
  models.py                        # 统一 Pydantic 数据模型
  main.py                          # 包内 CLI 入口

tests/
  test_shell_runner.py
  test_tool_selection.py
  test_fusion.py
  test_cli_smoke.py
```

### 2.1 当前工具选择策略（v2）

- 字段边界切分阶段：默认只选 1 个主工具（`Netzob` 或 `NEMESYS`）
- 字段语义推断阶段：默认只选 1 个主工具（`NetPlier` 或 `BinaryInferno`）
- 另外 2 个工具作为备份，不默认执行
- 触发备份条件：
  - 主工具执行失败或候选为空
  - 分段主工具质量不足（字段数过少/过多，或单字段跨度占比过高）
  - 语义主工具 `unknown` 占比过高（默认阈值 `>=0.70`）
  - 语义主工具语义过于单一（dominant ratio 过高，默认阈值 `>=0.85`）
  - 融合阶段对 `unknown` 增加惩罚，在分数接近时优先保留可解释语义（如 `id/length/checksum`）

## 3. 统一数据模型

核心模型位于 `src/testcrewai/models.py`：

- `TrafficProfile`
- `ToolDecision` / `ExecutionPlan`
- `FieldBoundaryCandidate`
- `FieldSemanticCandidate`
- `EvidenceItem`
- `ProtocolSchema`
- `AnalysisReport`
- `ProtocolReverseState`（Flow 状态）

## 4. 环境与安装

### 4.1 Python

- Python `>=3.10,<3.14`

### 4.2 安装依赖

```bash
# 推荐
pip install uv
uv sync
```

### 4.3 可选外部工具

- `tshark`（推荐安装）
- `scapy`（可选，安装后可增强本地报文解析）

即使外部工具缺失，系统仍会进入降级逻辑并继续输出结果。

## 5. 模型配置（DeepSeek）

本项目默认通过 CrewAI + LiteLLM 的模型字符串读取模型。

在 `.env` 中可配置：

```env
DEEPSEEK_API_KEY=your_key
DEEPSEEK_MODEL=deepseek/deepseek-chat
# 或者 MODEL=deepseek/deepseek-chat
```

如果不传 `--use-llm`，系统将主要依赖本地规则与工具，不强依赖在线 API。

## 6. 运行方式

```bash
python app/main.py --pcap examples/demo.pcap --output outputs/run_01 --print-json --use-llm
```

> 打印json，使用指定大模型参与决策


**可选参数**：

```bash
python app/main.py \
  --pcap examples/demo.pcapng \
  --output outputs/run_02 \
  --python-bin /usr/bin/python3 \
  --netzob-python-bin /root/venv/bin/python \
  --nemesys-python-bin /root/venv_nemesys/bin/python \
  --netplier-python-bin /root/venv_netplier/bin/python \
  --binaryinferno-python-bin /root/venv_binaryinferno/bin/python \
  --timeout 120 \
  --use-llm \
  --print-json
```

**这些可选参数含义如下：**

* `--pcap`
输入抓包文件路径（建议 .pcap/.pcapng）。

* `--output`
本次运行输出目录，会生成 traffic_profile.json、execution_plan.json、final_schema.json、report.md 等。

* `--python-bin`
全局 Python 解释器，给各子进程工具适配器用。
如果某个工具没单独指定解释器，就用它。

* `--netzob-python-bin`
仅 Netzob 适配器使用的 Python（通常是装了 Netzob 的虚拟环境 bin/python）。

* `--nemesys-python-bin`
仅 NEMESYS 适配器使用的 Python。

* `--netplier-python-bin`
仅 NetPlier 适配器使用的 Python。

* `--binaryinferno-python-bin`
仅 BinaryInferno 适配器使用的 Python。

* `--timeout`
工具子进程超时时间（秒）。超时会走降级/回退逻辑，而不是整条流程崩溃。

* `--use-llm`
开启大模型参与：
预处理阶段、工具选择阶段、融合阶段，以及各阶段注释。
需要环境里指定可用 API Key 以及 model类型。

* `--print-json`
终端打印最终 JSON 摘要（含产物路径、警告和错误信息、大模型输出的阶段注释），便于查看。




**env文件**：

```env
NETZOB_PYTHON_BIN=/root/venv/bin/python
NEMESYS_PYTHON_BIN=/root/venv_nemesys/bin/python
NETPLIER_PYTHON_BIN=/root/venv_netplier/bin/python
BINARYINFERNO_PYTHON_BIN=/root/venv_binaryinferno/bin/python
NETZOB_MODE=auto
NETZOB_IMPORT_LAYER=5
NETZOB_IMPORT_LAYER_CANDIDATES=5,4,3,2,1
NETZOB_NORMALIZE_CAPTURE=true
NEMESYS_HOME=/root/tools/nemesys
NEMESYS_MODE=auto
NEMESYS_SIGMA=0.6
NEMESYS_LAYER=2
NEMESYS_LAYER_CANDIDATES=2,3,4
NEMESYS_RELATIVE_TO_IP=true
NEMESYS_RELATIVE_TO_IP_MODE=auto
NEMESYS_DISABLE_REFINEMENT=false
NEMESYS_CONSENSUS_MIN_SUPPORT=0.60
NEMESYS_CONSENSUS_MAX_FIELDS=64
NEMESYS_DISABLE_CONSENSUS=false
NEMESYS_NORMALIZE_CAPTURE=true
NETPLIER_MAIN_PATH=/root/NetPlier/NetPlier/netplier/main.py
NETPLIER_MAFFT_MODE=einsi
NETPLIER_MULTITHREAD=true
NETPLIER_LAYER_CANDIDATES=5,4,3,2,1
NETPLIER_TIMEOUT_SEC=180
NETPLIER_MAX_PACKETS=40
NETPLIER_NORMALIZE_CAPTURE=true
OFFICIAL_CAPTURE_NORMALIZE=true
BINARYINFERNO_MAIN_PATH=/root/BinaryInferno/binaryinferno/binaryinferno/blackboard.py
BINARYINFERNO_DETECTORS=boundBE
BINARYINFERNO_MAX_MESSAGES=40
BINARYINFERNO_TIMEOUT_SEC=90
BINARYINFERNO_MAX_ATTEMPTS=3
BINARYINFERNO_ACCEPT_LOW_SIGNAL=true
SEGMENT_MIN_FIELDS_PER_CLUSTER=4
SEGMENT_MAX_FIELDS_PER_CLUSTER=64
SEGMENT_MAX_SPAN_RATIO=0.85
SEGMENT_MAX_SINGLE_BYTE_RATIO=0.60
SEGMENT_MIN_BOUNDARY_STABILITY=0.30
SEGMENT_MIN_COVERAGE_RATIO=0.55
SEMANTIC_UNKNOWN_RATIO_TRIGGER=0.70
SEMANTIC_DOMINANT_RATIO_TRIGGER=0.85
SEMANTIC_DOMINANT_MIN_CANDIDATES=5
FUSION_UNKNOWN_PENALTY=0.85
FUSION_PREFER_NON_UNKNOWN_RATIO=0.92
FUSION_PREFER_NON_GENERIC_RATIO=0.95
FUSION_SEMANTIC_COLLAPSE_RATIO=0.85
FUSION_SEMANTIC_COLLAPSE_PENALTY=0.82
FUSION_SEMANTIC_COLLAPSE_MIN_COUNT=8
FUSION_COLLAPSE_TYPES=type,id,unknown
FUSION_LARGE_FIELD_TYPE_PENALTY=0.78
FUSION_PAYLOAD_TAIL_BOOST=1.20
FUSION_LENGTH_HEADER_BOOST=1.10
FUSION_ID_WIDTH_BOOST=1.05
```

说明：上面既可以写解释器文件（如 `/root/venv/bin/python`），也可以直接写虚拟环境目录（如 `/root/venv`），程序会自动解析成 `bin/python`。
说明：`NETPLIER_MAX_PACKETS=40` 是当前 DHCP 样本上的稳定推荐值（可降低 NetPlier MAFFT 超时概率）。
说明：`NETPLIER_LAYER_CANDIDATES` 会在官方 NetPlier 导入失败时自动切换导入层重试。
说明：`BINARYINFERNO_MAX_ATTEMPTS` 会在官方 blackboard 提示区分度不足时自动切换 detector 组合重试。
说明：`BINARYINFERNO_ACCEPT_LOW_SIGNAL=true` 时，官方 hints 信号偏弱但有结构信息时也会优先采用官方路径，避免过早降级。
说明：`NEMESYS_CONSENSUS_*` 用于“官方分段结果共识压缩”，可抑制 NEMESYS 过分段导致的字段爆炸。
说明：`*_LAYER_CANDIDATES` 与 `*_RELATIVE_TO_IP_MODE=auto` 会在官方入口失败时自动探测更合适参数，提高官方路径稳定率。
说明：`OFFICIAL_CAPTURE_NORMALIZE=true` 会先把输入归一化为标准 pcap，再调用官方工具（可减少 pcapng/datalink 兼容问题）。
说明：`SEGMENT_MAX_SINGLE_BYTE_RATIO / SEGMENT_MIN_BOUNDARY_STABILITY / SEGMENT_MIN_COVERAGE_RATIO` 用于增强分段质量门控。
说明：`NETPLIER_MAX_PACKETS` 和 `BINARYINFERNO_MAX_MESSAGES` 主要用于提高官方工具稳定性，减少大流量时超时风险。
说明：`NEMESYS_MODE=auto` 时会优先调用官方 NEMESYS API（`SpecimenLoader + bcDeltaGaussMessageSegmentation`），失败自动降级到本地启发式分段。
说明：`FUSION_UNKNOWN_PENALTY` 与 `FUSION_PREFER_NON_UNKNOWN_RATIO` 用于避免“有意义语义”被 `unknown` 长期压制。
说明：`FUSION_SEMANTIC_COLLAPSE_*` 与 `FUSION_COLLAPSE_TYPES` 用于抑制“单工具单语义长期主导（如全 type / 全 id）”。
说明：`FUSION_LARGE_FIELD_TYPE_PENALTY / FUSION_PAYLOAD_TAIL_BOOST` 用于尾部大字段的结构先验（减少尾部被误判成 type）。

### 6.1 一键初始化 NEMESYS 独立环境

```bash
bash scripts/setup_nemesys_env.sh
```

默认会创建：

- `NEMESYS_HOME=/root/tools/nemesys`
- `NEMESYS_PYTHON_BIN=/root/venv_nemesys/bin/python`

## 7. 输出文件

每次运行至少产出：

```text
outputs/run_x/
├── traffic_profile.json
├── execution_plan.json
├── segment_candidates.json
├── nemesys_segments_raw.json      # 可选：选择了 NEMESYS 时生成
├── semantic_candidates.json
├── final_schema.json
├── report.md
└── run.log
```


说明：项目预处理优先按文件魔数识别 `pcap/pcapng`，后缀与魔数不一致也可处理并提示。



## 8. 版本核对建议（按 AGENTS.md）

```bash
# 1) 已安装版本
.venv/bin/python -c "import crewai; print(crewai.__version__)"

# 2) PyPI 最新版本
python - <<'PY'
import json, urllib.request
print(json.load(urllib.request.urlopen('https://pypi.org/pypi/crewai/json'))['info']['version'])
PY
```

当前工程依赖固定在 `crewai==1.11.0`，若需升级可执行：

```bash
uv sync --upgrade-package crewai
```


## 9. 复现指南
本章节是复现教程
### 9.1 复现步骤

适用于需要复现“官方工具调用链”。

1. 需准备四套工具环境（路径以自己环境为准）：
   - `NETZOB_PYTHON_BIN`
   - `NEMESYS_PYTHON_BIN`
   - `NETPLIER_PYTHON_BIN`
   - `BINARYINFERNO_PYTHON_BIN`

2. 复现步骤

```bash
git clone https://github.com/cyez-ly/protocols-reverse.git
cd protocols-reverse
git checkout main
# 配置环境
uv sync
# 配置.env
cp .env.example .env
```

.env文件修改为自己的路径：

```txt
# API key
OPENROUTER_API_KEY=YOUR_KEY_HERE
# 使用的模型
MODEL=openrouter/deepseek/deepseek-r1
# deepseek/deepseek-r1

# 工具各自的 Python 解释器（推荐写到 bin/python，最直观）
# 举例/root/venv_binaryinferno/bin/python
NETZOB_PYTHON_BIN=你的netzob路径
NEMESYS_PYTHON_BIN=你的nemesys路径
NETPLIER_PYTHON_BIN=你的netplier路径
BINARYINFERNO_PYTHON_BIN=你的binaryinferno路径


# NEMESYS 官方仓库根目录（应包含 src/nemere）
NEMESYS_HOME=/root/tools/nemesys

# NetPlier 官方入口（仓库里的 main.py）
NETPLIER_MAIN_PATH=/root/NetPlier/NetPlier/netplier/main.py

# BinaryInferno 官方入口（blackboard.py）
BINARYINFERNO_MAIN_PATH=/root/BinaryInferno/binaryinferno/binaryinferno/blackboard.py

```


3. 运行
```bash
python app/main.py --pcap <数据文件> --output outputs/run_01 --use-llm --print-json
```

