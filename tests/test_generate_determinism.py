"""End-to-end determinism of `generate` (CLAUDE.md invariant #5).

The manifest-level determinism check lives in test_manifest.py; this asserts the
stronger, user-facing promise: "compartir un lab = compartir su spec → artefactos
idénticos". Two independent `generate` runs of the same spec must produce a
byte-for-byte identical tree — Terraform + Ansible + deploy scripts + report AND
every secret — because ALL secrets (population user passwords and the two infra
keys) are now derived from population.seed. Nothing is per-deployer, so no
pre-seeding is needed: the spec alone fully determines the lab.
"""

from __future__ import annotations

import filecmp
import json
from types import SimpleNamespace

import forge
from _helpers import make_spec, write_spec


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
    assert _generate(spec_file, a) == 0
    assert _generate(spec_file, b) == 0
    _assert_tree_identical(a, b)


def test_infra_secrets_are_seed_deterministic(tmp_path):
    """The two infra credentials (admin/ansible) are a pure function of
    population.seed: identical across regenerates of the same spec, and different
    for a different seed. This is what makes lab-report.md fully reproducible from
    the spec (no per-deployer values)."""
    admin1, ansible1 = forge.derive_infra_secrets(1234)
    admin2, ansible2 = forge.derive_infra_secrets(1234)
    assert (admin1, ansible1) == (admin2, ansible2)
    assert admin1 != ansible1, "admin and ansible must draw from distinct seed streams"
    other_admin, _ = forge.derive_infra_secrets(9999)
    assert other_admin != admin1, "a different seed must yield a different admin password"

    # And they land, unchanged, in the generated secrets overlay.
    spec_file = write_spec(tmp_path, make_spec(name="det-secrets", seed=1234, vulns=["kerberoasting"]))
    out = tmp_path / "run"
    assert _generate(spec_file, out) == 0
    tf = json.loads((out / "terraform" / "azure" / "secrets.auto.tfvars.json").read_text(encoding="utf-8"))
    assert tf["admin_password"] == admin1
    assert tf["ansible_password"] == ansible1
