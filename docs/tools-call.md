# ==工具调用逻辑==（netzob、netplier、NEMESYS、binaryinferno）

**Netzob/NEMESYS**：优先官方 API（结构化、对齐更好）。
**NetPlier/BinaryInferno**：优先官方脚本/CLI（更贴近官方使用方式，环境隔离更稳）。


#### 1. `Netzob`（官方 API 优先）
- 调度入口：[`segmentation.py`](/root/crewAI/testcrewai/src/testcrewai/pipeline/segmentation.py:321)
- 先调用适配脚本：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:847)（`netzob_cli.py`）
- 模式参数传入：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:874)（`--mode`）
- 官方 API 真正调用：[`netzob_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netzob_cli.py:346)（`from netzob.all import Format, PCAPImporter`）
- `auto/official/heuristic` 切换：[`netzob_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netzob_cli.py:477)
- 官方失败后降级：[`netzob_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netzob_cli.py:513) 到 [`netzob_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netzob_cli.py:520)

#### 2. `NEMESYS`（官方 API 优先）
- 调度入口：[`segmentation.py`](/root/crewAI/testcrewai/src/testcrewai/pipeline/segmentation.py:346)
- 先调用适配脚本：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:939)（`nemesys_cli.py`）
- 模式参数传入：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1014)（`--mode`）
- 官方 API 真正调用：[`nemesys_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/nemesys_cli.py:147)（`from nemere...`）
- `auto/official/heuristic` 切换：[`nemesys_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/nemesys_cli.py:422)
- 官方失败后降级：[`nemesys_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/nemesys_cli.py:498) 到 [`nemesys_cli.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/nemesys_cli.py:504)

#### 3. `NetPlier`（官方脚本/CLI 优先）
- 调度入口：[`semantics.py`](/root/crewAI/testcrewai/src/testcrewai/pipeline/semantics.py:241)
- “官方优先”声明：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1101)
- 发现官方 `main.py`：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1134)
- 官方命令拼装并执行：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1218) 到 [`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1226)
- 官方兼容启动器（实际跑官方 main）：[`netplier_official_runner.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netplier_official_runner.py:42) 到 [`netplier_official_runner.py`](/root/crewAI/testcrewai/src/testcrewai/adapters/netplier_official_runner.py:72)
- 官方失败后回退本地脚本：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1304)（`netplier_cli.py`）

#### 4. `BinaryInferno`（官方脚本/CLI 优先）
- 调度入口：[`semantics.py`](/root/crewAI/testcrewai/src/testcrewai/pipeline/semantics.py:269)
- “官方优先”声明：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1357)
- 官方脚本命令（`blackboard.py --detectors ...`）并执行：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1453) 到 [`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1462)
- 官方成功标记：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1509)
- 官方失败后回退本地脚本：[`protocol_tools.py`](/root/crewAI/testcrewai/src/testcrewai/tools/protocol_tools.py:1541)（`binaryinferno_cli.py`）

**所有这些命令最终都统一由 [`shell_runner.py`](/root/crewAI/testcrewai/src/testcrewai/tools/shell_runner.py:15) 的 `subprocess.run` 执行。**