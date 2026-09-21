import os
import re

import yaml

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "service_manifest.yml")


def _manifest():
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f)


def test_heuristic_filetypes_are_valid_regex():
    manifest = _manifest()
    for heuristic in manifest["heuristics"]:
        re.compile(heuristic["filetype"])


def test_accepts_and_rejects_are_valid_regex():
    manifest = _manifest()
    re.compile(manifest["accepts"])
    re.compile(manifest["rejects"])


def test_docker_image_matches_version_file():
    manifest = _manifest()
    version_path = os.path.join(os.path.dirname(__file__), "..", "..", "VERSION")
    with open(version_path) as f:
        version = f.read().strip()
    assert manifest["docker_config"]["image"] == "kylemc54321/assemblyline-service-speakeasy:$SERVICE_TAG"
    assert re.match(r"^\d+\.\d+\.\d+\.stable\d+$", version)


def test_no_internet_access():
    manifest = _manifest()
    assert manifest["docker_config"]["allow_internet_access"] is False


def test_vendor_source_present():
    src = os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src")
    assert os.path.isdir(os.path.join(src, "speakeasy"))
    assert os.path.isfile(os.path.join(src, "pyproject.toml"))


def test_dos_fragments_are_rejected_but_real_pes_are_accepted():
    """AL types tiny junk (e.g. base64-decoded fragments) as executable/windows/dos; Speakeasy can only
    emulate PEs, so those always fail with 'not a PE'."""
    manifest = _manifest()
    assert re.fullmatch(manifest["rejects"], "executable/windows/dos")
    for pe_type in ("executable/windows/pe64", "executable/windows/pe32", "executable/windows/dll64"):
        assert re.fullmatch(manifest["accepts"], pe_type)
        assert not re.fullmatch(manifest["rejects"], pe_type)
