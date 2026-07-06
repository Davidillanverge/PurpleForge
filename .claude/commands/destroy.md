---
description: Tear down a lab to cost-zero and verify nothing is left behind — forge.py teardown
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DESTROY from the MAIN thread for: $ARGUMENTS

Teardown is deterministic — run it yourself with Bash; no subagent needed.

Destroy is hard to reverse — confirm the human intends to tear down THIS lab
before proceeding. Then:

- `python3 scripts/forge.py teardown specs/<lab>.yml`

`teardown` runs the generated `teardown.sh`: it starts any VMs that
`auto_shutdown` already deallocated (so destroy can delete their extensions),
runs `terraform destroy`, sweeps stray snapshots that would block the
resource-group delete, verifies the resource group is gone (a
`ResourceGroupNotFound` 404 IS the confirmation of cost-zero; a 200 means it is
NOT gone — it retries), and cleans up local session state (the `pf-ansible`
container and the `pf-lab` WireGuard interface).

Report the teardown result and confirm no billable resource remains
(`az resource list -g <lab>` should 404).
