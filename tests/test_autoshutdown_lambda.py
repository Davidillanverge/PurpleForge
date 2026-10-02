"""Unit tests for the AWS auto-shutdown Lambda's provisioning guard.

A first deploy that crosses the daily cron time must not be stopped underneath
Ansible. deploy.sh tags in-flight instances pf:provisioning=true and the Lambda
must skip them (AWS-DEPLOY-RUNBOOK: "hosts go UNREACHABLE mid site.yml").

boto3 isn't a test dependency, so we inject a fake `boto3` module before importing
the Lambda and drive its handler with a stub EC2 client.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from _helpers import REPO_ROOT

LAMBDA_PATH = REPO_ROOT / "templates" / "terraform" / "aws" / "lambda" / "stop_instances.py"


class _FakeEC2:
    def __init__(self, instances):
        self._instances = instances
        self.stopped = None

    def describe_instances(self, Filters=None):
        # Only running instances reach the Lambda's stop logic (it filters on it).
        return {"Reservations": [{"Instances": self._instances}]}

    def stop_instances(self, InstanceIds=None):
        self.stopped = list(InstanceIds)
        return {}


def _load_lambda(fake_ec2):
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda *a, **k: fake_ec2  # noqa: ARG005
    sys.modules["boto3"] = fake_boto3
    spec = importlib.util.spec_from_file_location("pf_stop_instances", LAMBDA_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _inst(iid, provisioning=False):
    tags = [{"Key": "lab", "Value": "lab-x"}]
    if provisioning:
        tags.append({"Key": "pf:provisioning", "Value": "true"})
    return {"InstanceId": iid, "Tags": tags}


def test_skips_provisioning_tagged_instances(monkeypatch):
    monkeypatch.setenv("LAB_NAME", "lab-x")
    ec2 = _FakeEC2([_inst("i-keep", provisioning=True), _inst("i-stop")])
    mod = _load_lambda(ec2)
    result = mod.handler({}, None)
    assert ec2.stopped == ["i-stop"]
    assert result["stopped"] == ["i-stop"]
    assert result["skipped"] == ["i-keep"]


def test_stops_all_when_none_provisioning(monkeypatch):
    monkeypatch.setenv("LAB_NAME", "lab-x")
    ec2 = _FakeEC2([_inst("i-a"), _inst("i-b")])
    mod = _load_lambda(ec2)
    result = mod.handler({}, None)
    assert sorted(ec2.stopped) == ["i-a", "i-b"]
    assert result["skipped"] == []


def test_no_stop_call_when_all_provisioning(monkeypatch):
    monkeypatch.setenv("LAB_NAME", "lab-x")
    ec2 = _FakeEC2([_inst("i-a", provisioning=True)])
    mod = _load_lambda(ec2)
    result = mod.handler({}, None)
    assert ec2.stopped is None  # stop_instances never called
    assert result["skipped"] == ["i-a"]
