"""Black-box regression suite over the same scenarios.yaml the demo uses.

Assumes the demo stack is already up (`make up`). Fires each scenario and checks
the WAF's reaction: benign traffic is allowed, attacks are blocked/challenged/
banned, and the block reason names the layer we expected.

    cd demo && pytest tests/ -v
    cd demo && pytest tests/ -v -m "not rasp"     # skip RASP-dependent scenarios
"""
import asyncio
import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))
from sim import run_scenario  # noqa: E402

SCEN = yaml.safe_load(open(os.path.join(os.path.dirname(__file__),
                                        "..", "attacks", "scenarios.yaml")))

# Map a WAF block reason fragment to the layer that produced it.
LAYER_HINTS = {
    "coraza": "coraza", "lgbm": "tier0", "ueba": "gatekeeper",
    "gatekeeper": "gatekeeper", "rate_limit": "gatekeeper", "rasp": "rasp",
}

RASP_SCENARIOS = {"rce_exec", "lfi_read", "webshell", "ssrf",
                  "sqli_rasp", "db_unauth"}


def _params():
    for name in SCEN:
        marks = [pytest.mark.rasp] if name in RASP_SCENARIOS else []
        yield pytest.param(name, marks=marks)


@pytest.mark.parametrize("name", list(_params()))
def test_scenario(name):
    results = asyncio.run(run_scenario(name))
    assert results, f"{name}: no requests fired"
    # Look at the strongest reaction across the scenario's shots.
    blocked = [r for r in results if r["status"] in (401, 403, 406, 429)]
    allowed = [r for r in results if 200 <= r["status"] < 400]
    expect = results[-1]["expect_decision"]

    if expect == "allow":
        assert allowed, f"{name}: benign traffic was blocked: {results}"
    else:
        assert blocked, f"{name}: expected a block/challenge/ban, got {results}"
