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
python app/main.py --pcap examples/demo.pcap --output outputs/run_01
```

可选参数：

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

也支持通过环境变量为不同工具设置解释器（优先级低于 CLI 参数）：

```bash
export NETZOB_PYTHON_BIN=/root/venv/bin/python
export NEMESYS_PYTHON_BIN=/root/venv_nemesys/bin/python
export NETPLIER_PYTHON_BIN=/root/venv_netplier/bin/python
export BINARYINFERNO_PYTHON_BIN=/root/venv_binaryinferno/bin/python
```

官方工具入口也可以通过环境变量指定：

```bash
export NETZOB_MODE=auto
export NETZOB_IMPORT_LAYER=5
export NETZOB_IMPORT_LAYER_CANDIDATES=5,4,3,2,1
export NETZOB_NORMALIZE_CAPTURE=true
export NEMESYS_HOME=/root/tools/nemesys
export NEMESYS_MODE=auto
export NEMESYS_SIGMA=0.6
export NEMESYS_LAYER=2
export NEMESYS_LAYER_CANDIDATES=2,3,4
export NEMESYS_RELATIVE_TO_IP=true
export NEMESYS_RELATIVE_TO_IP_MODE=auto
export NEMESYS_DISABLE_REFINEMENT=false
export NEMESYS_CONSENSUS_MIN_SUPPORT=0.60
export NEMESYS_CONSENSUS_MAX_FIELDS=64
export NEMESYS_DISABLE_CONSENSUS=false
export NEMESYS_NORMALIZE_CAPTURE=true
export NETPLIER_MAIN_PATH=/root/NetPlier/NetPlier/netplier/main.py
export NETPLIER_MAFFT_MODE=einsi
export NETPLIER_MULTITHREAD=true
export NETPLIER_LAYER_CANDIDATES=5,4,3,2,1
export NETPLIER_TIMEOUT_SEC=180
export NETPLIER_MAX_PACKETS=40
export NETPLIER_NORMALIZE_CAPTURE=true
export OFFICIAL_CAPTURE_NORMALIZE=true
export BINARYINFERNO_MAIN_PATH=/root/BinaryInferno/binaryinferno/binaryinferno/blackboard.py
export BINARYINFERNO_DETECTORS=boundBE
export BINARYINFERNO_MAX_MESSAGES=40
export BINARYINFERNO_TIMEOUT_SEC=90
export BINARYINFERNO_MAX_ATTEMPTS=3
export BINARYINFERNO_ACCEPT_LOW_SIGNAL=true
```

如果不想每次 `export`，可以直接写进项目根目录 `.env`，程序启动时会自动加载：

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

## 8. 样本覆盖建议（已升级为中大样本）

当前数据脚本已从“极小测试包”升级为“中大包量”样本，覆盖常见和不常见协议，并保留文本/二进制分类。
说明：项目预处理优先按文件魔数识别 `pcap/pcapng`，后缀与魔数不一致也可处理并提示。

### 8.1 一键下载并整理到 datasets

项目内置数据整理脚本：`scripts/prepare_datasets.py`，自动下载并分类：

- 常见 + 文本：HTTP/TLS 混合流、SIP+RTP、gRPC-Web
- 常见 + 二进制：DNS+mDNS、QUIC、HTTP/2、TLS1.2
- 不常见 + 文本：NetPerfMeter、gRPC stream reassembly
- 不常见 + 二进制：OPC UA(signed/encrypted-chunking)、logistics multicast

执行命令：

```bash
# 推荐：清理旧的小样本并重建
python scripts/prepare_datasets.py --root datasets --clean-old --force
```

生成目录：

```text
datasets/
├── common/text
├── common/binary
├── uncommon/text
├── uncommon/binary
└── manifests/
    ├── dataset_index.json
    └── dataset_index.csv
```

其中 `dataset_index.json/csv` 会记录每个样本的来源链接、协议类型、分类、文件大小、`packet_count` 和 SHA256。

## 9. 测试

```bash
python -m unittest discover -s tests -v
```

## 10. 版本核对建议（按 AGENTS.md）

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

## 11. 后续扩展建议

1. 优化官方 NetPlier 运行性能（大样本时 MAFFT 耗时较高，可增加采样/分片策略）。
2. 增加协议模板导出（如 Kaitai Struct 或自定义 DSL）。
3. 增加 Web UI（FastAPI + 前端）并复用当前 JSON 中间结果。
4. 加入更多统计特征和聚类算法（时序、方向、状态机推断）。
