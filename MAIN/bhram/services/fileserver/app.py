"""
BHRAM Deception File Server
Provides:
  1. Observable file access — every access is logged (feeds telemetry in Part 2)
  2. Orchestrator API — allows the AI/ML orchestrator to:
       - create decoy files
       - delete decoy files
       - modify decoy file content
       - move decoy files
       - change file metadata
       - list the current decoy file structure

SECURITY:
  - Bound to loopback/backend network only
  - No direct attacker access
  - File paths are validated — no directory traversal
  - No shell execution
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Settings ──────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    fileserver_root: str = "/srv/company-files"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "bhram_db"
    postgres_user: str = "bhram_user"
    postgres_password: str = "devpassword_not_for_production"

settings = Settings()
FILE_ROOT = Path(settings.fileserver_root)
FILE_ROOT.mkdir(parents=True, exist_ok=True)


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="BHRAM File Server",
    description=(
        "Deception file server with full orchestrator management API.\n\n"
        "All files served are fictional decoy content. "
        "Every access is observable and logged. "
        "This API is bound to the backend network and NOT attacker-accessible."
    ),
    version="1.0.0",
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class DecoyFileCreate(BaseModel):
    filename: str
    filepath: str
    content: str = ""
    content_type: str = "text/plain"
    bait_level: int = 1

    @field_validator("filepath")
    @classmethod
    def validate_path(cls, v: str) -> str:
        # Prevent directory traversal
        p = Path(v)
        if ".." in p.parts:
            raise ValueError("Directory traversal detected in filepath")
        return v


class DecoyFileMove(BaseModel):
    source_path: str
    destination_path: str

    @field_validator("source_path", "destination_path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if ".." in Path(v).parts:
            raise ValueError("Directory traversal detected")
        return v


class FileMetadataUpdate(BaseModel):
    filepath: str
    content_type: Optional[str] = None
    bait_level: Optional[int] = None
    notes: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_path(relative: str) -> Path:
    """Resolve a relative path safely within FILE_ROOT."""
    resolved = (FILE_ROOT / relative.lstrip("/")).resolve()
    if not str(resolved).startswith(str(FILE_ROOT)):
        raise HTTPException(status_code=400, detail="Path traversal rejected")
    return resolved


def file_info(p: Path) -> Dict[str, Any]:
    stat = p.stat()
    return {
        "filename": p.name,
        "filepath": str(p.relative_to(FILE_ROOT)),
        "size_bytes": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "is_dir": p.is_dir(),
    }


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health() -> dict:
    return {
        "status": "healthy",
        "service": "bhram-fileserver",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_root": str(FILE_ROOT),
        "file_count": sum(1 for _ in FILE_ROOT.rglob("*") if _.is_file()),
    }


# ── File Listing ──────────────────────────────────────────────────────────────

@app.get("/files", tags=["File Operations"])
async def list_files(path: str = "") -> dict:
    """List files in the decoy file server — for orchestrator use."""
    target = safe_path(path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    files = []
    dirs = []
    if target.is_dir():
        for item in sorted(target.iterdir()):
            info = file_info(item)
            if item.is_dir():
                dirs.append(info)
            else:
                files.append(info)

    return {
        "path": path or "/",
        "directories": dirs,
        "files": files,
        "total_files": len(files),
    }


# ── Orchestrator API — File CRUD ──────────────────────────────────────────────

@app.post("/files/create", tags=["Orchestrator API"], status_code=status.HTTP_201_CREATED)
async def create_decoy_file(payload: DecoyFileCreate) -> dict:
    """
    Create a new decoy file at the specified path.
    Called by the AI/ML orchestrator to deploy bait files.
    """
    target = safe_path(payload.filepath)
    target.parent.mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(target, "w", encoding="utf-8") as f:
        await f.write(payload.content)

    return {
        "success": True,
        "message": f"Decoy file created: {payload.filepath}",
        "filepath": str(target.relative_to(FILE_ROOT)),
        "size_bytes": target.stat().st_size,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@app.delete("/files/delete", tags=["Orchestrator API"])
async def delete_decoy_file(filepath: str) -> dict:
    """Remove a decoy file — called by orchestrator during environment reconstruction."""
    target = safe_path(filepath)
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    return {"success": True, "message": f"Deleted: {filepath}"}


@app.put("/files/modify", tags=["Orchestrator API"])
async def modify_decoy_file(filepath: str, content: str) -> dict:
    """Modify the content of an existing decoy file."""
    target = safe_path(filepath)
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")

    async with aiofiles.open(target, "w", encoding="utf-8") as f:
        await f.write(content)

    return {
        "success": True,
        "message": f"Modified: {filepath}",
        "size_bytes": target.stat().st_size,
        "modified_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/files/move", tags=["Orchestrator API"])
async def move_decoy_file(payload: DecoyFileMove) -> dict:
    """Move a decoy file to a new location."""
    src = safe_path(payload.source_path)
    dst = safe_path(payload.destination_path)
    if not src.exists():
        raise HTTPException(status_code=404, detail="Source file not found")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {
        "success": True,
        "message": f"Moved: {payload.source_path} → {payload.destination_path}",
    }


@app.get("/files/content", tags=["Orchestrator API"])
async def get_file_content(filepath: str) -> dict:
    """Read a decoy file's content — for orchestrator inspection."""
    target = safe_path(filepath)
    if not target.exists() or target.is_dir():
        raise HTTPException(status_code=404, detail="File not found")

    async with aiofiles.open(target, "r", encoding="utf-8", errors="replace") as f:
        content = await f.read()

    return {
        "filepath": filepath,
        "content": content,
        "size_bytes": target.stat().st_size,
    }


# ── Structure overview ────────────────────────────────────────────────────────

@app.get("/structure", tags=["File Operations"])
async def get_structure() -> dict:
    """Return the full decoy file tree for orchestrator reference."""
    def walk(p: Path) -> dict:
        if p.is_file():
            return {"name": p.name, "type": "file", "size": p.stat().st_size}
        children = [walk(c) for c in sorted(p.iterdir())]
        return {"name": p.name, "type": "directory", "children": children}

    return {
        "root": str(FILE_ROOT),
        "tree": [walk(c) for c in sorted(FILE_ROOT.iterdir())],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
