"""Configuration and platform detection for StackWise."""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Engine(StrEnum):
    OLLAMA = "ollama"
    MLX = "mlx"
    RULES_ONLY = "rules-only"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


ALL_MODULES = ["compute", "data", "network", "security", "observability", "cost", "discovery"]

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:14b"
DEFAULT_REGIONS = ["us-east-1"]


@dataclass
class Settings:
    """Runtime settings resolved from CLI flags, env vars, and defaults."""

    profile: str | None = None
    regions: list[str] = field(default_factory=lambda: list(DEFAULT_REGIONS))
    modules: list[str] = field(default_factory=lambda: list(ALL_MODULES))
    model: str = DEFAULT_MODEL
    engine: Engine = Engine.OLLAMA
    ollama_url: str = DEFAULT_OLLAMA_URL
    output_dir: Path = Path("./reports")
    data_dir: Path = field(
        default_factory=lambda: Path(d)
        if (d := os.environ.get("STACKWISE_DATA_DIR"))
        else (Path.home() / ".stackwise")
    )
    llm_chunk_size: int = 30
    llm_max_chunks: int = 10
    suppressed_rules: list[str] = field(default_factory=list)
    scan_max_workers: int = 4  # max parallel regions per scanner
    # Cost Explorer (ce:GetCostAndUsage) bills $0.01/request, unlike every other
    # scanner call, which is a free control-plane API. Off by default cost stays
    # opt-out rather than opt-in, but this lets a user avoid it entirely.
    skip_cost_explorer: bool = False

    def scans_dir(self, account_id: str) -> Path:
        path = self.data_dir / "scans" / account_id
        path.mkdir(parents=True, exist_ok=True)
        return path


def detect_platform() -> dict:
    """Detect OS, architecture, and available GPU acceleration."""
    info: dict = {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "has_nvidia": False,
        "has_metal": False,
    }

    if info["os"] == "darwin":
        # Apple Silicon always has Metal
        if info["arch"] == "arm64":
            info["has_metal"] = True
    elif info["os"] == "linux":
        # Check for NVIDIA GPU via nvidia-smi
        info["has_nvidia"] = shutil.which("nvidia-smi") is not None

    return info


def auto_select_engine() -> Engine:
    """Pick the best available LLM engine for the current platform."""
    plat = detect_platform()

    if plat["os"] == "darwin" and plat["has_metal"]:
        # Prefer MLX on Apple Silicon if mlx_lm is installed
        try:
            import mlx_lm  # noqa: F401

            return Engine.MLX
        except ImportError:
            pass

    # Ollama is the cross-platform default
    if shutil.which("ollama") is not None:
        return Engine.OLLAMA

    return Engine.RULES_ONLY


def resolve_settings(
    *,
    profile: str | None = None,
    regions: str | None = None,
    modules: str | None = None,
    model: str | None = None,
    engine: str | None = None,
    output_dir: str | None = None,
    suppressed_rules: str | None = None,
    skip_cost_explorer: bool = False,
) -> Settings:
    """Build Settings from CLI flags with env var fallbacks."""
    s = Settings()

    s.profile = profile or os.environ.get("AWS_PROFILE")

    if regions:
        s.regions = [r.strip() for r in regions.split(",")]
    elif env_regions := os.environ.get("STACKWISE_REGIONS"):
        s.regions = [r.strip() for r in env_regions.split(",")]

    # Always include us-east-1 for global/regional services (IAM, GuardDuty, etc.)
    if "us-east-1" not in s.regions:
        s.regions = ["us-east-1"] + s.regions

    if modules:
        s.modules = [m.strip() for m in modules.split(",")]
        unknown = [m for m in s.modules if m not in ALL_MODULES]
        if unknown:
            raise ValueError(
                f"Unknown module(s): {', '.join(unknown)}. "
                f"Valid modules: {', '.join(ALL_MODULES)}"
            )

    s.model = model or os.environ.get("STACKWISE_MODEL", DEFAULT_MODEL)

    if engine:
        s.engine = Engine(engine)
    else:
        s.engine = auto_select_engine()

    s.ollama_url = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_URL)

    if output_dir:
        s.output_dir = Path(output_dir)

    if suppressed_rules:
        s.suppressed_rules = [r.strip() for r in suppressed_rules.split(",")]
    elif env_supp := os.environ.get("STACKWISE_SUPPRESSED_RULES"):
        s.suppressed_rules = [r.strip() for r in env_supp.split(",")]

    if env_workers := os.environ.get("STACKWISE_SCAN_MAX_WORKERS"):
        try:
            s.scan_max_workers = max(1, int(env_workers))
        except ValueError:
            pass

    s.skip_cost_explorer = skip_cost_explorer or _env_flag("STACKWISE_SKIP_COST_EXPLORER")

    return s


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")
