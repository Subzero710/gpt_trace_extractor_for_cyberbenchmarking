from pathlib import Path
import tomllib

from gpt_trace_storage import __version__
from gpt_trace_storage.main import app


def test_storage_versions_are_consistent() -> None:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    package_version = tomllib.loads(
        pyproject.read_text(encoding="utf-8")
    )["project"]["version"]

    assert __version__ == package_version
    assert app.version == package_version
