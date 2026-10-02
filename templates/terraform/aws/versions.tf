terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    # archive packs the auto_shutdown Lambda's inline source into a .zip at
    # plan time (no external build step) — see auto_shutdown.tf.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # CLAUDE.md invariant #4: state lives in a remote backend with locking,
  # never local. Partial config on purpose — the actual bucket/key/table are
  # lab-specific and supplied at init time:
  #   terraform init -backend-config=backend.hcl
  # scripts/forge.py generate writes backend.hcl next to this file from
  # lab.name. One shared S3 bucket + DynamoDB lock table holds every lab's
  # state as a separate key (the AWS analogue of the shared Azure storage
  # account); the bucket name must be globally unique, so backend.hcl ships a
  # placeholder to override after the one-time bootstrap, NOT a working
  # default — see .claude/skills/infra-aws/SKILL.md.
  backend "s3" {}
}
