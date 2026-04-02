from __future__ import annotations

import os
from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class ProtocolReverseCrew:
    """Crew definitions used by the protocol reverse pipeline."""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    def _model_name(self) -> str:
        return os.getenv("DEEPSEEK_MODEL") or os.getenv("MODEL") or "deepseek/deepseek-chat"

    @agent
    def preprocess_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["preprocess_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def tool_selector_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["tool_selector_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def segmentation_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["segmentation_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def semantic_inference_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["semantic_inference_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def fusion_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["fusion_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @agent
    def report_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["report_agent"],  # type: ignore[index]
            llm=self._model_name(),
            reasoning=False,
            verbose=True,
        )

    @task
    def preprocess_task(self) -> Task:
        return Task(
            config=self.tasks_config["preprocess_task"],  # type: ignore[index]
        )

    @task
    def tool_selection_task(self) -> Task:
        return Task(
            config=self.tasks_config["tool_selection_task"],  # type: ignore[index]
        )

    @task
    def segmentation_task(self) -> Task:
        return Task(
            config=self.tasks_config["segmentation_task"],  # type: ignore[index]
        )

    @task
    def semantic_inference_task(self) -> Task:
        return Task(
            config=self.tasks_config["semantic_inference_task"],  # type: ignore[index]
        )

    @task
    def fusion_task(self) -> Task:
        return Task(
            config=self.tasks_config["fusion_task"],  # type: ignore[index]
        )

    @task
    def report_task(self) -> Task:
        return Task(
            config=self.tasks_config["report_task"],  # type: ignore[index]
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
