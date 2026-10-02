"""PurpleForge auto-shutdown Lambda (CLAUDE.md invariant #4).

Stops every EC2 instance tagged lab=<LAB_NAME> in this region. Triggered by the
EventBridge Scheduler cron in auto_shutdown.tf. Stopping (not terminating) an
instance preserves its EBS volume + the clean-state snapshot, so the lab can be
started again next day; `terraform destroy` is what returns cost to zero.
"""

import os

import boto3


def handler(event, context):
    lab = os.environ["LAB_NAME"]
    ec2 = boto3.client("ec2")

    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:lab", "Values": [lab]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )["Reservations"]

    ids = [i["InstanceId"] for r in reservations for i in r["Instances"]]
    if ids:
        ec2.stop_instances(InstanceIds=ids)
        print(f"PurpleForge auto-shutdown: stopped {len(ids)} instance(s) for lab '{lab}': {ids}")
    else:
        print(f"PurpleForge auto-shutdown: no running instances for lab '{lab}'.")

    return {"stopped": ids}
