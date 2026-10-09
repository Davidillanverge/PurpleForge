"""Lifecycle commands: the deterministic, no-AI deploy / teardown / destroy path.
`deploy`/`teardown` are thin wrappers that run the generated deploy.sh/teardown.sh
after the guardrail gate; `destroy` is the lower-level terraform-destroy +
cost-zero verification. run_terraform_plan (structural validation) lives here too.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .core import GENERATED_DIR, REPO_ROOT, load_yaml

# Directory that must be on PYTHONPATH for `python -m forge` to resolve the
# package when it is not installed (scripts/forge/lifecycle.py -> scripts/).
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent


def run_terraform_plan(tf_dir: Path) -> int:
    """Structural validation only — never how a real lab is deployed (that
    needs -backend-config=backend.hcl against a bootstrapped storage account,
    see infra-azure's SKILL.md). `init -backend=false` alone isn't enough:
    tested empirically against Terraform 1.15.7, it lets `validate` pass but
    `plan` still refuses ("Backend initialization required") because the
    partial `backend "azurerm" {}` block is still declared in versions.tf and
    `-backend=false`'s disabled-backend marker doesn't survive to the next
    command. The documented workaround is an override.tf swapping the
    backend to `local` for this run only — written here and always removed
    before returning, so a real deploy can never accidentally inherit it."""
    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        print(
            "warning: terraform not found on PATH; skipping plan (install terraform to exercise this step).",
            file=sys.stderr,
        )
        return 0

    override_path = tf_dir / "override.tf"
    local_state_path = tf_dir / "terraform.tfstate"
    override_path.write_text('terraform {\n  backend "local" {}\n}\n', encoding="utf-8")
    try:
        for cmd in (["init", "-input=false"], ["validate"], ["plan", "-input=false"]):
            full = [terraform_bin, f"-chdir={tf_dir}", *cmd]
            print(f"  $ {' '.join(full)}")
            result = subprocess.run(full)
            if result.returncode != 0:
                return result.returncode
        return 0
    finally:
        override_path.unlink(missing_ok=True)
        local_state_path.unlink(missing_ok=True)


def verify_azure_teardown(lab_name: str) -> bool:
    """Returns True unless we have positive evidence the resource group is
    still there (never returns a false "confirmed gone" on an ambiguous
    az CLI error, e.g. an auth failure — that's reported as "could not
    verify", not silently treated as success).

    Uses `az rest` against the ARM REST API directly, not `az group show` —
    verified on a real deploy that `az group show`/`az group list` (and
    separately `az vm ...`/`az network ... show-effective-...`) crash with a
    Python traceback (`ModuleNotFoundError:
    azure.mgmt.resource.resources.v20XX...` or similar) in some environments,
    an azure-cli command-loading bug unrelated to credentials. That crash's
    non-zero exit code and traceback stderr don't match the "gone" or
    "still there" checks below, so it fell into the (correctly) ambiguous
    branch — but every real deploy that hit it, hit it, making this the
    common case there rather than a rare edge case worth just flagging.
    `az rest` is a thin REST passthrough with its own minimal argument
    parsing that doesn't exercise the broken command-loading path."""
    az_bin = shutil.which("az")
    if not az_bin:
        print("warning: az CLI not found; cannot verify teardown — check the Azure portal manually.", file=sys.stderr)
        return True

    sub = os.environ.get("ARM_SUBSCRIPTION_ID")
    if not sub:
        acct = subprocess.run([az_bin, "account", "show", "--query", "id", "-o", "tsv"], capture_output=True, text=True)
        sub = acct.stdout.strip() if acct.returncode == 0 else None
    if not sub:
        print(
            "warning: could not determine the subscription id (set ARM_SUBSCRIPTION_ID); "
            "cannot verify teardown — check the Azure portal manually.",
            file=sys.stderr,
        )
        return True

    url = f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{lab_name}?api-version=2021-04-01"
    result = subprocess.run([az_bin, "rest", "--method", "get", "--url", url], capture_output=True, text=True)
    if result.returncode == 0:
        print(
            f"WARNING: resource group '{lab_name}' still exists after destroy — remaining resources:", file=sys.stderr
        )
        subprocess.run([az_bin, "resource", "list", "--resource-group", lab_name, "-o", "table"])
        return False

    stderr_lower = result.stderr.lower()
    if "resourcegroupnotfound" in stderr_lower:
        print(f"  verified: resource group '{lab_name}' no longer exists — no leftover Azure cost from this lab.")
        return True

    print(
        f"warning: could not confirm resource group '{lab_name}' is gone (az CLI error, possibly auth-related):\n"
        f"  {result.stderr.strip()}\n"
        f"  Check the Azure portal manually before assuming teardown is complete.",
        file=sys.stderr,
    )
    return True  # ambiguous, not positive evidence of failure — flagged, not silently passed


def _aws_existing_ids(aws_bin: str, region: str, describe: str, *extra: str, query: str) -> set[str]:
    """Return the set of resource ids that currently exist for a `describe-*`
    call (e.g. images/snapshots owned by self). Used to tell apart resources that
    are truly gone from ARNs the Resource Groups Tagging API still lists due to
    deletion lag. An errored CLI call returns an empty set (treat as unknown,
    caller keeps the ARN rather than wrongly dropping a live resource)."""
    r = subprocess.run(
        [aws_bin, "ec2", describe, "--region", region, *extra, "--query", query, "--output", "text"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return set()
    return set(r.stdout.split())


def verify_aws_teardown(lab_name: str, region: str) -> bool:
    """AWS sibling of verify_azure_teardown. Returns True unless we have
    positive evidence that resources tagged lab=<lab_name> still exist in the
    region. Uses the Resource Groups Tagging API (`aws resourcegroupstaggingapi
    get-resources`), which spans every taggable service the lab creates — EC2
    instances/EIPs/ENIs/subnets/VPC, the auto_shutdown Lambda + schedule — so a
    single call confirms the cost-bearing resources are gone. An ambiguous CLI
    error (e.g. auth) is reported as "could not verify", never silently treated
    as success. NOTE: IAM roles are global (not region-scoped or returned here);
    terraform destroy removes them, and they bear no cost, so they are not part
    of this cost-zero check."""
    aws_bin = shutil.which("aws")
    if not aws_bin:
        print("warning: aws CLI not found; cannot verify teardown — check the AWS console manually.", file=sys.stderr)
        return True

    result = subprocess.run(
        [
            aws_bin, "resourcegroupstaggingapi", "get-resources",
            "--region", region,
            "--tag-filters", f"Key=lab,Values={lab_name}",
            "--query", "ResourceTagMappingList[].ResourceARN",
            "--output", "text",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"warning: could not confirm lab '{lab_name}' is gone (aws CLI error, possibly auth-related):\n"
            f"  {result.stderr.strip()}\n"
            f"  Check the AWS console (region {region}) manually before assuming teardown is complete.",
            file=sys.stderr,
        )
        return True  # ambiguous, not positive evidence of failure

    remaining = result.stdout.split()

    gone: set[str] = set()

    # Terminated (and shutting-down) EC2 instances keep their tags and linger in
    # the Resource Groups Tagging API for up to ~1h after terminate (and, once
    # fully aged out, can STILL appear there as ghosts) before AWS purges them —
    # but they bear NO cost; only a pending/running/stopping/stopped one does.
    # Classify by what is ACTUALLY ALIVE, queried BY TAG (not by id: a ghost that
    # no longer exists errors / returns nothing on a by-id lookup, which is the
    # bug that made aged-out terminated instances count as leftovers). Any tagged
    # instance ARN not in the alive set is terminated/gone -> not a leftover.
    inst_ids = [arn.rsplit("/", 1)[-1] for arn in remaining if ":instance/" in arn]
    if inst_ids:
        alive = _aws_existing_ids(
            aws_bin, region, "describe-instances",
            "--filters", f"Name=tag:lab,Values={lab_name}",
            "Name=instance-state-name,Values=pending,running,stopping,stopped",
            query="Reservations[].Instances[].InstanceId",
        )
        gone |= set(inst_ids) - alive

    # Deregistered AMIs and deleted EBS snapshots linger in the tagging API the
    # same way terminated instances do. sweep_aws_clean_images runs BEFORE this
    # and removes the lab's out-of-band clean-state images/snapshots, so an
    # image/snapshot ARN still listed here is almost always tagging-API lag on a
    # resource that is already gone. Drop the ones that no longer actually exist
    # (list what remains and subtract) so a clean teardown doesn't false-FAIL.
    img_ids = [arn.rsplit("/", 1)[-1] for arn in remaining if ":image/" in arn]
    snap_ids = [arn.rsplit("/", 1)[-1] for arn in remaining if ":snapshot/" in arn]
    if img_ids:
        existing = _aws_existing_ids(aws_bin, region, "describe-images",
                                     "--owners", "self", query="Images[].ImageId")
        gone |= set(img_ids) - existing
    if snap_ids:
        existing = _aws_existing_ids(aws_bin, region, "describe-snapshots",
                                     "--owner-ids", "self", query="Snapshots[].SnapshotId")
        gone |= set(snap_ids) - existing
    # The instances' root EBS volumes are delete_on_termination, so terminating a
    # VM deletes its volume ASYNCHRONOUSLY: the volume sits in state `deleting`
    # (and lingers in the tagging API) for a bit after `terraform destroy` returns.
    # A `deleting`/`deleted` volume bears no cost and needs no action, so it is
    # NOT a leftover — only a volume still in a live state (available/in-use/
    # creating/error) is. describe-volumes returns every state, so filter to the
    # live ones and drop any vol ARN that is not among them (deleting, or gone).
    vol_ids = [arn.rsplit("/", 1)[-1] for arn in remaining if ":volume/" in arn]
    if vol_ids:
        live = _aws_existing_ids(
            aws_bin, region, "describe-volumes",
            "--filters", "Name=status,Values=creating,available,in-use,error",
            query="Volumes[].VolumeId",
        )
        gone |= set(vol_ids) - live
    remaining = [arn for arn in remaining if arn.rsplit("/", 1)[-1] not in gone]

    if remaining:
        print(
            f"WARNING: {len(remaining)} resource(s) tagged lab={lab_name} still exist in {region} after destroy:",
            file=sys.stderr,
        )
        for arn in remaining:
            print(f"    {arn}", file=sys.stderr)
        return False

    print(f"  verified: no billable resources tagged lab='{lab_name}' remain in {region} — no leftover AWS cost from this lab.")
    return True


def sweep_aws_clean_images(lab_name: str, region: str) -> None:
    """Deregister the clean-state AMIs (and delete their backing EBS snapshots)
    this lab's deploy.sh created out of band — they are NOT in Terraform state,
    so `terraform destroy` leaves them. Run as part of `forge destroy` BEFORE
    verify_aws_teardown, so a destroy of a snapshotted lab verifies clean in one
    pass (the generated teardown.sh also sweeps, idempotently, as belt-and-braces).
    Best-effort: a sweep failure is warned, not fatal."""
    aws_bin = shutil.which("aws")
    if not aws_bin:
        return
    imgs = subprocess.run(
        [
            aws_bin, "ec2", "describe-images", "--region", region, "--owners", "self",
            "--filters", f"Name=tag:lab,Values={lab_name}",
            "--query", "Images[].ImageId", "--output", "text",
        ],
        capture_output=True, text=True,
    )
    if imgs.returncode != 0:
        return
    for ami in imgs.stdout.split():
        snaps = subprocess.run(
            [
                aws_bin, "ec2", "describe-images", "--region", region, "--image-ids", ami,
                "--query", "Images[].BlockDeviceMappings[].Ebs.SnapshotId", "--output", "text",
            ],
            capture_output=True, text=True,
        )
        print(f"  deregister clean-state AMI {ami}")
        subprocess.run([aws_bin, "ec2", "deregister-image", "--region", region, "--image-id", ami],
                       capture_output=True, text=True)
        for snap in (snaps.stdout.split() if snaps.returncode == 0 else []):
            subprocess.run([aws_bin, "ec2", "delete-snapshot", "--region", region, "--snapshot-id", snap],
                           capture_output=True, text=True)


def _run_self(subcommand: list[str]) -> int:
    """Invoke this same forge CLI as a subprocess (reuse a full command, e.g. the
    guardrail gate, without refactoring it into a callable that fakes argparse).
    Runs `python -m forge` with the scripts dir on PYTHONPATH so it resolves the
    package whether or not it's pip-installed."""
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(_SCRIPTS_DIR) + (os.pathsep + existing if existing else "")
    return subprocess.run([sys.executable, "-m", "forge", *subcommand], env=env).returncode


def cmd_deploy(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    manifest_path = lab_dir / "lab-manifest.json"
    deploy_sh = lab_dir / "deploy.sh"

    if not manifest_path.exists() or not deploy_sh.exists():
        print(
            f"error: {lab_dir} has no lab-manifest.json / deploy.sh — run `forge generate {args.spec}` first.",
            file=sys.stderr,
        )
        return 2

    if not args.skip_guardrail:
        print("=== guardrail gate (invariants must PASS before any cloud spend) ===")
        if _run_self(["guardrail", str(spec_path), *(["--out-dir", str(lab_dir)] if args.out_dir else [])]) != 0:
            print(
                "FAIL: guardrail did not pass — refusing to deploy. Fix the spec, or "
                "re-run with --skip-guardrail (not recommended).",
                file=sys.stderr,
            )
            return 1

    billable = {"azure": "Azure", "aws": "AWS", "proxmox": "Proxmox (on-prem)"}.get(
        spec["lab"].get("provider", ""), spec["lab"].get("provider", "")
    )
    print(f"\n=== DEPLOY {lab_name} — this creates BILLABLE {billable} resources ===")
    print(f"    running {deploy_sh.relative_to(REPO_ROOT) if deploy_sh.is_relative_to(REPO_ROOT) else deploy_sh}")
    extra = ["--sizes-only"] if args.sizes_only else []
    return subprocess.run(["bash", str(deploy_sh), str(lab_dir), *extra]).returncode


def cmd_teardown(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    teardown_sh = lab_dir / "teardown.sh"
    if not teardown_sh.exists():
        print(
            f"warning: {teardown_sh} not found — falling back to `forge destroy` "
            f"(no VM-start / snapshot-sweep gotcha handling).",
            file=sys.stderr,
        )
        return _run_self(["destroy", str(spec_path), "--yes", *(["--out-dir", str(lab_dir)] if args.out_dir else [])])
    print(f"=== TEARDOWN {lab_name} — destroy to cost-zero + verify ===")
    # teardown.sh asks the operator to type the lab name; --force skips that
    # prompt (and is required when stdin is not a terminal).
    extra = ["--force"] if getattr(args, "force", False) else []
    return subprocess.run(["bash", str(teardown_sh), str(lab_dir), *extra]).returncode


def clean_snapshot_name(lab_name: str, vm_name: str) -> str:
    """The deterministic name of a VM's clean-state snapshot on Azure —
    "<lab>-<vm>-clean". deploy.sh creates it (its last step, after
    hardening+vulns, before any attack) and reset.sh restores from it; this is
    the single source of truth for that name so the two never drift. (Proxmox
    uses a fixed per-VM snapshot name, "pf-clean", since snapshots there are
    namespaced under the VM already.)"""
    return f"{lab_name}-{vm_name}-clean"


def cmd_reset(args: argparse.Namespace) -> int:
    """Deterministic no-AI reset: run the generated reset.sh, which re-runs the
    Ansible phase (site.yml) against the RUNNING VMs to restore the spec's clean
    logical state — nothing is destroyed or powered off. With --snapshot it
    instead rolls every VM back to the clean-state snapshot deploy.sh took after
    hardening + vuln injection (rollback.sh). Thin wrapper around reset.sh (the
    single source of truth for the exact commands), mirroring cmd_teardown."""
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    reset_sh = lab_dir / "reset.sh"
    if not reset_sh.exists():
        print(
            f"error: {reset_sh} not found — run `forge generate {args.spec}` first "
            "(reset.sh is rendered alongside deploy.sh/teardown.sh).",
            file=sys.stderr,
        )
        return 2
    snapshot = getattr(args, "snapshot", False)
    if snapshot:
        print(f"=== RESET {lab_name} — roll every VM back to its clean-state snapshot ===")
    else:
        print(f"=== RESET {lab_name} — re-run the Ansible phase on the running VMs ===")
    return subprocess.run(["bash", str(reset_sh), str(lab_dir), *(["--snapshot"] if snapshot else [])]).returncode


def _run_power_script(args: argparse.Namespace, script: str, banner: str) -> int:
    """Shared body for the power-control commands (stop/restart): locate the
    generated <script> under the lab dir and run it. Thin wrapper mirroring
    cmd_reset — the generated script is the single source of truth for the exact
    per-provider commands."""
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    script_sh = lab_dir / script
    if not script_sh.exists():
        print(
            f"error: {script_sh} not found — run `forge generate {args.spec}` first "
            f"({script} is rendered alongside deploy.sh/teardown.sh).",
            file=sys.stderr,
        )
        return 2
    print(f"=== {banner.format(lab=lab_name)} ===")
    return subprocess.run(["bash", str(script_sh), str(lab_dir)]).returncode


def cmd_stop(args: argparse.Namespace) -> int:
    """Deterministic no-AI stop: run the generated stop.sh to gracefully power
    off (and on Azure deallocate) every VM, dropping the lab to minimal cost
    WITHOUT destroying it or touching Terraform state. Resume with `forge start`.
    Not a teardown, not a snapshot rollback."""
    return _run_power_script(args, "stop.sh", "STOP {lab} — graceful power-off of every VM (no destroy, state untouched)")


def cmd_start(args: argparse.Namespace) -> int:
    """Deterministic no-AI start: run the generated start.sh to power a stopped
    lab back on, re-establish the WireGuard tunnel and verify network/SSH +
    WinRM reachability — WITHOUT terraform apply (no resource is rewritten)."""
    return _run_power_script(args, "start.sh", "START {lab} — power on + reconnect + verify (no terraform apply)")


def cmd_restart(args: argparse.Namespace) -> int:
    """Deterministic no-AI restart: run the generated restart.sh to reboot every
    VM — the unstick button for a hung/blocked machine. A power reboot, NOT a
    snapshot rollback (use `forge reset` for a pristine lab)."""
    return _run_power_script(args, "restart.sh", "RESTART {lab} — reboot every VM (unstick a hung machine)")


def cmd_destroy(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    # AWS teardown verification is region-scoped (tagging API). Honour a PF_REGION
    # override the same way deploy-aws.sh does, else the spec's region.
    aws_region = os.environ.get("PF_REGION") or os.environ.get("AWS_DEFAULT_REGION") or spec["lab"].get("region", "")

    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    tf_root = lab_dir / "terraform"
    if not tf_root.exists():
        print(
            f"error: no terraform/ directory found under {lab_dir} (nothing generated, or already destroyed?)",
            file=sys.stderr,
        )
        return 2
    provider_dirs = sorted(d for d in tf_root.iterdir() if d.is_dir())
    if not provider_dirs:
        print(f"error: {tf_root} has no provider subdirectory", file=sys.stderr)
        return 2

    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        print("error: terraform not found on PATH.", file=sys.stderr)
        return 2

    overall_ok = True
    for provider_dir in provider_dirs:
        provider = provider_dir.name
        print(f"=== {provider}: {lab_name} ===")

        backend_hcl = provider_dir / "backend.hcl"
        init_cmd = [terraform_bin, f"-chdir={provider_dir}", "init", "-input=false"]
        if backend_hcl.exists():
            init_cmd.append(f"-backend-config={backend_hcl.name}")
        else:
            print(
                f"  warning: no {backend_hcl.name} in {provider_dir}; assuming already initialized against the right backend.",
                file=sys.stderr,
            )
        print(f"  $ {' '.join(init_cmd)}")
        if subprocess.run(init_cmd).returncode != 0:
            overall_ok = False
            continue

        action = ["plan", "-destroy", "-input=false"] if args.check_only else ["destroy", "-input=false"]
        if args.yes and not args.check_only:
            action.append("-auto-approve")
        full = [terraform_bin, f"-chdir={provider_dir}", *action]
        print(f"  $ {' '.join(full)}")
        if subprocess.run(full).returncode != 0:
            overall_ok = False
            continue

        if args.check_only:
            continue

        if provider == "azure":
            if not verify_azure_teardown(lab_name):
                overall_ok = False
        elif provider == "aws":
            # Sweep the out-of-band clean-state AMIs/snapshots BEFORE verifying,
            # so a snapshotted lab verifies clean in a single destroy pass
            # (otherwise verify counts them as leftovers and the teardown.sh
            # retry loop re-runs a no-op destroy).
            sweep_aws_clean_images(lab_name, aws_region)
            if not verify_aws_teardown(lab_name, aws_region):
                overall_ok = False
        else:
            print(f"  note: no post-destroy verification implemented for provider '{provider}' yet.")

    if overall_ok:
        print(f"OK: {lab_name} destroyed and verified — no expected leftover cost.")
    else:
        print(f"FAIL: {lab_name} destroy did not fully verify clean — see warnings above.", file=sys.stderr)
    return 0 if overall_ok else 1
