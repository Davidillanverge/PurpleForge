---
description: Tear down a lab to cost-zero and verify nothing is left behind
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DESTROY from the MAIN thread for: $ARGUMENTS

Destroy is hard to reverse — confirm the human intends to tear down THIS lab
before proceeding. Then dispatch `deploy-operator` in teardown mode:

- `python3 scripts/forge.py destroy specs/<lab>.yml --yes`
- Verify cost-zero: the resource group must be gone. A `ResourceGroupNotFound`
  404 IS the confirmation; a 200 with a provisioningState means it is NOT gone —
  retry. Clean up local session state (WireGuard `pf-lab`, the `pf-ansible`
  container) too.

Report the teardown result and confirm no billable resource remains.
