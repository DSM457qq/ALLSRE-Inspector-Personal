from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ToolCommand(BaseModel):
    command: str = Field(min_length=1, max_length=16_384)
    timeout: int = Field(default=30, ge=1, le=180)
    terminalId: str | None = None
    # Retained only so the existing OpenCode plugin payload remains compatible.
    assetId: int | None = None
    rawInput: bool | None = None
    classification: Literal["READ_ONLY", "MUTATING", "DESTRUCTIVE"] | None = None


class TaskFileWrite(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=4_000_000)
