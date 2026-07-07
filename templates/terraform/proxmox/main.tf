# A Proxmox resource pool groups every VM this lab creates, the on-prem analog
# of the Azure resource group (var.lab_name): it makes the lab enumerable for
# teardown/verification (`pvesh get /pools/<lab>`) and keeps a shared cluster
# tidy. All VMs below set pool_id to this pool.
resource "proxmox_virtual_environment_pool" "lab" {
  pool_id = var.lab_name
  comment = "PurpleForge lab ${var.lab_name}"
}

# NOTE on auto_shutdown (CLAUDE.md invariant #4): Proxmox VE has no native
# Terraform resource equivalent to Azure's DevTest auto-shutdown schedule, so
# it is NOT enforced here. It is a deploy-time concern on this provider — the
# proxmox branch of deploy.sh (iteration 2) installs a scheduled `qm shutdown`
# for this pool's VMs. Cost-zero teardown is still `terraform destroy` removing
# every VM in this pool.
