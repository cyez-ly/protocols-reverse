# 协议逆向系统执行流程与调用关系图

本文档用于说明本项目从 CLI 启动到结果落盘的完整调用链，包括：

- 各阶段执行顺序
- 各文件之间的调用关系
- tools/adapters 的子进程执行关系
- 每阶段输入/输出产物

## 1. 端到端执行流程（Flow 主链路）

```mermaid
flowchart TD
    U[用户命令<br/>python app/main.py --pcap ... --output ...] --> A[app/main.py]
    A --> B[src/testcrewai/main.py run/execute]
    B --> C[ProtocolReverseFlow.kickoff]

    C --> D[bootstrap<br/>初始化输出目录/日志/路径]
    D --> E[run_preprocess<br/>预处理]
    E --> F[run_tool_selection<br/>工具选择]
    F --> G[run_segmentation<br/>字段分割]
    G --> H[run_semantic_inference<br/>语义推断]
    H --> I[run_fusion<br/>结果融合]
    I --> J[run_report<br/>报告生成]
    J --> K[finish<br/>输出摘要]

    E --> E1[traffic_profile.json]
    F --> F1[execution_plan.json]
    G --> G1[segment_candidates.json]
    H --> H1[semantic_candidates.json]
    I --> I1[final_schema.json]
    J --> J1[report.md]
    K --> K1[run.log / llm_policy.json]
```

## 2. 文件级调用关系（主流程）

```mermaid
flowchart LR
    CLI[app/main.py] --> ENTRY[src/testcrewai/main.py]
    ENTRY --> FLOW[src/testcrewai/workflows/protocol_reverse_flow.py]

    FLOW --> PRE[src/testcrewai/pipeline/preprocess.py]
    FLOW --> SEL[src/testcrewai/pipeline/tool_selection.py]
    FLOW --> SEG[src/testcrewai/pipeline/segmentation.py]
    FLOW --> SEM[src/testcrewai/pipeline/semantics.py]
    FLOW --> FUS[src/testcrewai/pipeline/fusion.py]
    FLOW --> REP[src/testcrewai/pipeline/report.py]

    PRE --> IO[src/testcrewai/utils/io.py]
    SEL --> IO
    SEG --> IO
    SEM --> IO
    FUS --> IO
    REP --> IO
    FLOW --> LOG[src/testcrewai/utils/logging.py]
```

## 3. Tools 与 Adapters 调用图（子进程层）

```mermaid
flowchart LR
    PRE[PreprocessAgentStage] --> T[TsharkTool.run]
    T --> SR1[ShellRunner.run]
    SR1 --> C1[tshark -r <pcap> -q -z io,phs]

    SEG[SegmentationAgentStage] --> NZ[NetzobTool.run]
    NZ --> SR2[ShellRunner.run]
    SR2 --> A1[python adapters/netzob_cli.py ...]

    SEG --> NM[NemesysTool.run]
    NM --> SR3[ShellRunner.run]
    SR3 --> A2[python adapters/nemesys_cli.py ...]

    SEM[SemanticInferenceAgentStage] --> NP[NetPlierAdapter.run]
    NP --> NP_OFF[官方优先]
    NP_OFF --> SR4[ShellRunner.run]
    SR4 --> A3[python adapters/netplier_official_runner.py --main <official main.py> -- ...]
    NP --> NP_FB[失败回退]
    NP_FB --> SR5[ShellRunner.run]
    SR5 --> A4[python adapters/netplier_cli.py ...]

    SEM --> BI[BinaryInfernoAdapter.run]
    BI --> BI_OFF[官方优先]
    BI_OFF --> SR6[ShellRunner.run]
    SR6 --> A5[python <official blackboard.py> --detectors ...]
    BI --> BI_FB[失败回退]
    BI_FB --> SR7[ShellRunner.run]
    SR7 --> A6[python adapters/binaryinferno_cli.py ...]

    A1 --> CM[adapters/common.py]
    A2 --> CM
    A4 --> CM
    A6 --> CM
```

## 4. 各阶段输入与输出

| 阶段 | 主要输入 | 主要调用文件 | 主要输出 |
|---|---|---|---|
| bootstrap | CLI 参数 | `workflows/protocol_reverse_flow.py` | 初始化状态、日志路径、产物路径 |
| preprocess | `pcap/pcapng` | `pipeline/preprocess.py` | `traffic_profile.json` |
| tool_selection | `traffic_profile.json`（内存对象） | `pipeline/tool_selection.py` | `execution_plan.json` |
| segmentation | `traffic_profile.json` + `execution_plan.json` | `pipeline/segmentation.py` + `tools/protocol_tools.py` | `segment_candidates.json` |
| semantics | `segment_candidates.json` + `traffic_profile.json` + `execution_plan.json` | `pipeline/semantics.py` + `tools/protocol_tools.py` | `semantic_candidates.json` |
| fusion | 边界候选 + 语义候选 + profile | `pipeline/fusion.py` | `final_schema.json` |
| report | 所有中间结果 + final schema | `pipeline/report.py` | `report.md` |
| finish | 全部状态 | `workflows/protocol_reverse_flow.py` | 终端摘要、`llm_policy.json`、`run.log` |

## 5. 官方路径与降级路径（关键机制）

- `NetzobTool`：调用 `adapters/netzob_cli.py`，脚本内支持 official/heuristic/auto。
- `NemesysTool`：调用 `adapters/nemesys_cli.py`，支持 official/heuristic/auto。
- `NetPlierAdapter`：先尝试官方 `main.py`（通过 `netplier_official_runner.py`），失败后回退 `netplier_cli.py`。
- `BinaryInfernoAdapter`：先尝试官方 `blackboard.py`，失败后回退 `binaryinferno_cli.py`。
- 所有外部命令最终统一走 `tools/shell_runner.py`，并返回标准结构 `ShellCommandResult`。

## 6. LLM 在系统中的位置（受控参与）

LLM 不直接替代底层统计/解析，而是作为策略层增强：

- 预处理审查：`_apply_llm_preprocess_review`
- 工具选择二次裁决：`_refine_execution_plan_with_llm`
- 融合阶段语义仲裁：`_apply_llm_fusion_arbitration`
- 阶段性说明注释：`_collect_llm_note`

对应文件：`src/testcrewai/workflows/protocol_reverse_flow.py`。


