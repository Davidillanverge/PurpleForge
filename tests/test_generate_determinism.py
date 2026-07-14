"""End-to-end determinism of `generate` (CLAUDE.md invariant #5).

The manifest-level determinism check lives in test_manifest.py; this asserts the
stronger, user-facing promise: "compartir un lab = compartir su spec → artefactos
idénticos". Two independent `generate` runs of the same spec must produce a
byte-for-byte identical tree (Terraform + Ansible + deploy scripts + report).

The ONE thing that is deliberately NOT reproducible is the per-deployer infra
secret pair (admin/ansible passwords — drawn from the CSPRNG, invariant #5's
explicit carve-out). So both runs are pre-seeded with the same
secrets.auto.tfvars.json, which `load_existing_infra_secrets` reuses — isolating
the test to what the invariant actually promises is identical.
"""

from __future__ import annotations

import filecmp
import json
from types import SimpleNamespace

import forge
from _helpers import make_spec, write_spec

FIXED_SECRETS = {"admin_password": "Fixed_Admin_Pw_1!", "ansible_password": "Fixed_Ansible_Pw_1!"}


def _seed_infra_secrets(out_dir, provider: str) -> None:
    sec_dir = out_dir / "terraform" / provider
    sec_dir.mkdir(parents=True, exist_ok=True)
    (sec_dir / "secrets.auto.tfvars.json").write_text(json.dumps(FIXED_SECRETS), encoding="utf-8")


def _generate(spec_file, out_dir) -> int:
    return forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out_dir), plan=False))


def _assert_tree_identical(a, b) -> None:
    a_files = {p.relative_to(a) for p in a.rglob("*") if p.is_file()}
    b_files = {p.relative_to(b) for p in b.rglob("*") if p.is_file()}
    assert a_files == b_files, f"file sets differ: only in a={a_files - b_files}, only in b={b_files - a_files}"
    mismatches = [str(rel) for rel in sorted(a_files) if not filecmp.cmp(a / rel, b / rel, shallow=False)]
    assert not mismatches, f"byte-differing files across two generate runs: {mismatches}"


def test_azure_generate_is_byte_identical_across_runs(tmp_path):
    spec = make_spec(
        name="det-azure",
        provider="azure",
        members=1,
        services=["mssql"],
        vulns=["kerberoasting", "mssql-weak-sa", "asreproast"],
        edr=True,
        baseline="cis-l1",
        deception=2,
        users=25,
    )
    spec_file = write_spec(tmp_path, spec)
    a, b = tmp_path / "run-a", tmp_path / "run-b"
    for d in (a, b):
        _seed_infra_secrets(d, "azure")
    assert _generate(spec_file, a) == 0
    assert _generate(spec_file, b) == 0
    _assert_tree_identical(a, b)


def test_proxmox_generate_is_byte_identical_across_runs(tmp_path):
    spec = make_spec(
        name="det-proxmox",
        provider="proxmox",
        region="lab-node-1",
        members=1,
        vulns=["dcsync-acl", "unconstrained-delegation"],
        users=15,
    )
    spec_file = write_spec(tmp_path, spec)
    a, b = tmp_path / "run-a", tmp_path / "run-b"
    for d in (a, b):
        _seed_infra_secrets(d, "proxmox")
    assert _generate(spec_file, a) == 0
    assert _generate(spec_file, b) == 0
    _assert_tree_identical(a, b)


def test_generate_reuses_seeded_infra_secrets(tmp_path):
    """A generate over an out_dir that already holds secrets.auto.tfvars.json must
    reuse it verbatim (never re-randomize) — the mechanism the determinism test
    above relies on, asserted directly."""
    spec = make_spec(name="det-reuse", provider="azure", vulns=["kerberoasting"])
    spec_file = write_spec(tmp_path, spec)
    out = tmp_path / "run"
    _seed_infra_secrets(out, "azure")
    assert _generate(spec_file, out) == 0
    written = json.loads((out / "terraform" / "azure" / "secrets.auto.tfvars.json").read_text(encoding="utf-8"))
    assert written == FIXED_SECRETS
