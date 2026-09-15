"""End-to-end TestHelper-based test. The vendored Speakeasy CLI is never actually
invoked here -- subprocess.run is mocked to write a canned, schema-accurate report
(see test/unit/fixtures.py) to the --output path it was given, so the sample fixture's
own bytes are just an arbitrary placeholder, never a real (or real-shaped) executable.
"""
import json
import os
import subprocess
from unittest.mock import patch

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

from test.unit.fixtures import SUCCESS_REPORT

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

service_class = load_module_by_path(
    "speakeasy_service.speakeasy_service.Speakeasy", os.path.join(os.path.dirname(__file__), "..")
)
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


def _fake_run(cmd, **kwargs):
    out_path = cmd[cmd.index("--output") + 1]
    with open(out_path, "w") as f:
        json.dump(SUCCESS_REPORT, f)
    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


@pytest.mark.parametrize("sample", th.result_list())
@patch("speakeasy_service.runner.subprocess.run", side_effect=_fake_run)
def test_sample(mock_run, sample):
    th.run_test_comparison(sample)
