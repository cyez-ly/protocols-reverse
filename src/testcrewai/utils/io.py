from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def ensure_dir(path: str | Path) -> Path:
    output_path = Path(path)
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def write_json(path: str | Path, payload: Any) -> Path:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(payload, BaseModel):
        serializable = payload.model_dump(mode="json")
    else:
        serializable = payload

    with file_path.open("w", encoding="utf-8") as file_obj:
        json.dump(serializable, file_obj, ensure_ascii=False, indent=2)
    return file_path


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def write_text(path: str | Path, content: str) -> Path:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as file_obj:
        file_obj.write(content)
    return file_path
