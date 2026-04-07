from __future__ import annotations

import logging
from pathlib import Path

"""
    日志初始化

    在 Flow 的 bootstrap 阶段初始化，后续每个阶段都用同一个 logger 打印进度
    
"""


# 会同时配置：文件日志（写到 run.log）；终端日志（控制台输出）
def setup_logger(log_path: str | Path, logger_name: str = "protocol_reverse") -> logging.Logger:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.propagate = False
    return logger
