from __future__ import annotations

import argparse
import logging
import os

import uvicorn

from .app import create_app
from .config import load_settings


def run() -> None:
    parser = argparse.ArgumentParser(prog="allsre-inspector-personal")
    parser.add_argument("--config", help="configuration file path")
    args = parser.parse_args()
    settings = load_settings(args.config)
    level = os.getenv("ALLSRE_INSPECTOR_LOG_LEVEL", "info").lower()
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level=level)


if __name__ == "__main__":
    run()
