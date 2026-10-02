"""PurpleForge auto-shutdown Lambda (CLAUDE.md invariant #4).

Stops every EC2 instance tagged lab=<LAB_NAME> in this region. Triggered by the
EventBridge Scheduler cron in auto_shutdown.tf. Stopping (not terminating) an
instance preserves its EBS volume + the clean-state snapshot, so the lab can be
started again next day; `terraform destroy` is what returns cost to zero.

Provisioning guard: a first deploy that crosses the cron's wall-clock time would
otherwise get its instances stopped underneath Ansible (mid AD-promotion /
population), breaking the run. deploy.sh tags the instances `pf:provisioning=true`
between `terraform apply` and the clean-state snapshot, and this Lambda skips any
instance carrying that tag — so the schedule never interrupts a deploy in flight.
"""

import os

import boto3

PROVISIONING_TAG = "pf:provisioning"


def _is_provisioning(instance) -> bool:
    return any(
        t.get("Key") == PROVISIONING_TAG and str(t.get("Value")).lower() == "true"
        for t in instance.get("Tags", [])
    )


def handler(event, context):
    lab = os.environ["LAB_NAME"]
    ec2 = boto3.client("ec2")

    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:lab", "Values": [lab]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )["Reservations"]

    instances = [i for r in reservations for i in r["Instances"]]
    skipped = [i["InstanceId"] for i in instances if _is_provisioning(i)]
    ids = [i["InstanceId"] for i in instances if not _is_provisioning(i)]

    if skipped:
        print(f"PurpleForge auto-shutdown: skipping {len(skipped)} instance(s) still provisioning: {skipped}")
    if ids:
        ec2.stop_instances(InstanceIds=ids)
        print(f"PurpleForge auto-shutdown: stopped {len(ids)} instance(s) for lab '{lab}': {ids}")
    else:
        print(f"PurpleForge auto-shutdown: no running instances to stop for lab '{lab}'.")

    return {"stopped": ids, "skipped": skipped}
