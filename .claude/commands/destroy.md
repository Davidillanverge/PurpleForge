---
description: Tear down a lab to cost-zero and verify nothing is left behind — forge teardown
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DESTROY from the MAIN thread for: $ARGUMENTS

Deterministic — run it yourself with Bash. Destroy is hard to reverse: confirm
the human intends to tear down THIS lab first. Then:

- `forge teardown specs/<lab>.yml --force`

(`--force` because you already confirmed with the human: run non-interactively,
`teardown.sh` refuses to destroy without either a typed lab name or `--force`.)

`teardown.sh` starts any VMs `auto_shutdown` deallocated (so extensions can be
deleted), runs `terraform destroy`, sweeps stray snapshots blocking the RG
delete, verifies the RG is gone (`ResourceGroupNotFound` 404 = cost-zero; a 200
means NOT gone — it retries), and cleans up local state (`pf-ansible` container,
`pf-lab` WireGuard interface) and, only after a verified destroy, purges local
residue (`.terraform/`, lock file, local tfstate, `ssh_keys/`, deploy overlays,
`terraform-outputs.json`, Ansible caches).

Report the result and confirm no billable resource remains (`az resource list -g
<lab>` should 404).
