from __future__ import annotations
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from kali_workstation.contracts import SPECS, canonical_bytes, manifest
from kali_workstation.server import verify_manifest

def test_manifest_exact_and_no_wrappers():
    path=Path(__file__).parents[1]/'tool-manifest.json'
    assert canonical_bytes(manifest())==canonical_bytes(json.loads(path.read_text()))
    assert manifest()['app_id']=='kali-workstation' and manifest()['version']=='3.0.0'
    assert 'resize_terminal' in SPECS and 'observe_screen' in SPECS
    assert 'read_file' not in SPECS and 'download' not in SPECS
    verify_manifest(path)
    with pytest.raises(ValidationError):
        SPECS['exec_command'][1].model_validate({'command':'pwd','read_file':'oops'})
