"""Unit tests for verify_aws_teardown's leftover-vs-lag classification.

Regression guard for a live finding (lifecycle-smoke-lab, 2026-10-09): the
instances' root EBS volumes are delete_on_termination, so `terraform destroy`
returns while they are still in state `deleting` and the Resource Groups
Tagging API keeps listing them for a while. Those volumes bear no cost and
need no action, so they must NOT be counted as leftovers — otherwise a clean
teardown false-FAILs and the retry loop burns all its attempts. We stub the
`aws` CLI so no account is needed.
"""

from __future__ import annotations

import forge
from forge import lifecycle


def _fake_aws(mapping):
    """Return a fake subprocess.run that dispatches on the aws subcommand,
    yielding the stdout mapped for (subcommand) — e.g. 'resourcegroupstaggingapi',
    'describe-instances', 'describe-volumes', ... Unmapped -> empty stdout."""
    class R:
        def __init__(self, out): self.returncode = 0; self.stdout = out; self.stderr = ""
    def run(cmd, *a, **k):
        # calls aren't uniform (some have "ec2" at [1], _aws_existing_ids puts the
        # verb at [1]); match whichever mapped key appears anywhere in the argv.
        key = next((k for k in mapping if k in cmd), "")
        return R(mapping.get(key, ""))
    return run


def test_deleting_volume_is_not_a_leftover(monkeypatch):
    acct = "arn:aws:ec2:eu-west-1:1:"
    tagged = f"{acct}volume/vol-DEL {acct}instance/i-TERM {acct}snapshot/snap-GONE"
    mapping = {
        "resourcegroupstaggingapi": tagged,
        "describe-instances": "i-TERM",           # terminated -> dropped
        "describe-images": "",
        "describe-snapshots": "",                  # snap gone -> dropped
        "describe-volumes": "",                    # NO live volume (vol-DEL is deleting) -> dropped
    }
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: "/usr/bin/aws")
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_aws(mapping))
    assert lifecycle.verify_aws_teardown("lab", "eu-west-1") is True


def test_live_volume_is_a_leftover(monkeypatch):
    acct = "arn:aws:ec2:eu-west-1:1:"
    mapping = {
        "resourcegroupstaggingapi": f"{acct}volume/vol-LIVE",
        "describe-instances": "",
        "describe-images": "",
        "describe-snapshots": "",
        "describe-volumes": "vol-LIVE",            # still available/in-use -> real leftover
    }
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: "/usr/bin/aws")
    monkeypatch.setattr(lifecycle.subprocess, "run", _fake_aws(mapping))
    assert lifecycle.verify_aws_teardown("lab", "eu-west-1") is False
