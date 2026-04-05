#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

# ROOT == 根目录
ROOT = Path(__file__).resolve().parents[1]

# SRC == 根目录/src
SRC = ROOT / "src"

# 允许执行 `python app/main.py` 时正确导入 src 包。
if str(SRC) not in sys.path:
    # 把 src 加入搜索路径
    sys.path.insert(0, str(SRC))

# 实际 cli逻辑在包内入口。
from testcrewai.main import run


if __name__ == "__main__":
    run()
