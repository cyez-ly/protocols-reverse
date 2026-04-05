from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field

"""
    CrewAI 官方模板工具示例
"""

class MyCustomToolInput(BaseModel):
    """MyCustomTool 的输入参数结构。"""

    argument: str = Field(..., description="工具参数说明。")


class MyCustomTool(BaseTool):
    name: str = "自定义工具示例"
    description: str = (
        "用于演示 CrewAI 自定义工具的最小实现。"
    )
    args_schema: Type[BaseModel] = MyCustomToolInput

    def _run(self, argument: str) -> str:
        # 在这里替换成真实逻辑，例如调用本地命令或处理输入文件。
        return f"示例工具已收到参数: {argument}"
