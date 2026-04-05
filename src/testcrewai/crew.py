from __future__ import annotations

import os
from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class ProtocolReverseCrew:
    """Crew 定义：把 agents.yaml / tasks.yaml 映射为 CrewAI 可执行对象。"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    def _model_name(self) -> str:
        # 优先使用 .env 中配置的模型名，未配置时回退到默认值（默认是ds-v3）。
        return os.getenv("DEEPSEEK_MODEL") or os.getenv("MODEL") or "deepseek/deepseek-chat"

    @agent
    def preprocess_agent(self) -> Agent:
        # 预处理智能体：负责流量特征抽取解释。
        return Agent(
            config=self.agents_config["preprocess_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,  # 执行期间日志的详细程度，默认为false
        )

    @agent
    def tool_selector_agent(self) -> Agent:
        # 工具选择智能体：根据特征选择主工具与备份工具。
        return Agent(
            config=self.agents_config["tool_selector_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def segmentation_agent(self) -> Agent:
        # 分段智能体：关注字段边界候选质量。
        return Agent(
            config=self.agents_config["segmentation_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def semantic_inference_agent(self) -> Agent:
        # 语义智能体：给字段打语义标签并说明依据。
        return Agent(
            config=self.agents_config["semantic_inference_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def fusion_agent(self) -> Agent:
        # 融合智能体：做冲突裁决与最终结构整合。
        return Agent(
            config=self.agents_config["fusion_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def report_agent(self) -> Agent:
        # 报告智能体：输出可读的 Markdown 分析报告。
        return Agent(
            config=self.agents_config["report_agent"], 
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @task
    def preprocess_task(self) -> Task:
        # 与 preprocess_agent 对应。
        return Task(
            config=self.tasks_config["preprocess_task"],  # type: ignore[index]
        )

    @task
    def tool_selection_task(self) -> Task:
        # 与 tool_selector_agent 对应。
        return Task(
            config=self.tasks_config["tool_selection_task"],  # type: ignore[index]
        )

    @task
    def segmentation_task(self) -> Task:
        # 与 segmentation_agent 对应。
        return Task(
            config=self.tasks_config["segmentation_task"],  # type: ignore[index]
        )

    @task
    def semantic_inference_task(self) -> Task:
        # 与 semantic_inference_agent 对应。
        return Task(
            config=self.tasks_config["semantic_inference_task"],  # type: ignore[index]
        )

    @task
    def fusion_task(self) -> Task:
        # 与 fusion_agent 对应。
        return Task(
            config=self.tasks_config["fusion_task"],  # type: ignore[index]
        )

    @task
    def report_task(self) -> Task:
        # 与 report_agent 对应。
        return Task(
            config=self.tasks_config["report_task"],  # type: ignore[index]
        )

    @crew
    def crew(self) -> Crew:
        # 采用顺序执行(sequential)；本项目主调度仍由 Flow 负责。
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
