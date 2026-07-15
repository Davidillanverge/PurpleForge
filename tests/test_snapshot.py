"""Clean-state snapshot / reset (CLAUDE.md deploy order: SNAPSHOT is the last
deploy step, before any attack; `forge reset` restores it between exercises).

The live az/qm restore can't run here (no cloud), so these lock the deterministic
+ rendered parts: the snapshot name helper, that reset.sh is generated and
references the right snapshot, that deploy.sh takes the snapshot after site.yml,
and cmd_reset's pre-flight guards.
"""

from __future__ import annotations

from types import SimpleNamespace

import forge
from _helpers import make_spec, write_spec


def _generate(tmp_path, **spec_kwargs):
    # All secrets are seed-derived, so generate is hermetic — no pre-seeding needed.
    spec_file = write_spec(tmp_path, make_spec(**spec_kwargs))
    out = tmp_path / "out"
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    return spec_file, out


def test_clean_snapshot_name_is_deterministic():
    assert forge.clean_snapshot_name("kanto", "dc01") == "kanto-dc01-clean"
    assert forge.clean_snapshot_name("kanto", "dc01") == forge.clean_snapshot_name("kanto", "dc01")


def test_azure_deploy_snapshots_after_site_yml(tmp_path):
    _, out = _generate(tmp_path, provider="azure", vulns=["kerberoasting"])
    deploy = (out / "deploy.sh").read_text(encoding="utf-8")
    assert "snapshot_clean" in deploy
    assert "az snapshot create" in deploy
    # the snapshot must be the LAST provisioning step: after run_site, before "DEPLOY COMPLETE".
    assert deploy.index("run_site") < deploy.index("snapshot_clean\n  log \"DEPLOY COMPLETE")


def test_azure_reset_sh_rendered_with_clean_snapshot_name(tmp_path):
    _, out = _generate(tmp_path, provider="azure", vulns=["kerberoasting"])
    reset = out / "reset.sh"
    assert reset.exists()
    body = reset.read_text(encoding="utf-8")
    assert '${LAB}-${vm}-clean' in body  # matches clean_snapshot_name's format
    assert "az vm update" in body and "--os-disk" in body


def test_proxmox_reset_sh_uses_pf_clean(tmp_path):
    _, out = _generate(tmp_path, provider="proxmox", region="node-1", vulns=["kerberoasting"])
    reset = (out / "reset.sh").read_text(encoding="utf-8")
    assert "pf-clean" in reset and "rollback" in reset
    deploy = (out / "deploy.sh").read_text(encoding="utf-8")
    assert "snapname=pf-clean" in deploy


def test_reset_missing_spec_returns_2(tmp_path):
    rc = forge.cmd_reset(SimpleNamespace(spec=str(tmp_path / "nope.yml"), out_dir=None))
    assert rc == 2


def test_reset_missing_reset_sh_returns_2(tmp_path):
    spec_file = write_spec(tmp_path, make_spec(name="no-artifacts"))
    empty_out = tmp_path / "empty"
    empty_out.mkdir()
    rc = forge.cmd_reset(SimpleNamespace(spec=str(spec_file), out_dir=str(empty_out)))
    assert rc == 2
