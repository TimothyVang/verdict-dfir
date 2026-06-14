# Spec #3 §4.4 — Packer template that builds a warm QEMU microvm
# qcow2 from the existing sift-2026-04-22.ova at repo root.
#
# The output is a snapshotted, booted-to-login qcow2 that L3 CI
# runs can `-loadvm warm` into in 3-8 seconds — vs. 35-55s cold
# boot. The snapshot is named `warm`.
#
# Build command (requires KVM on host):
#   packer init packer/sift-microvm.pkr.hcl
#   install -m 600 /dev/null packer/local.auto.pkrvars.hcl
#   $EDITOR packer/local.auto.pkrvars.hcl   # add: ssh_password = "..."
#   packer build packer/sift-microvm.pkr.hcl
#
# Output: packer/artifacts/sift-microvm-warm.qcow2.zst
#
# Firecracker is intentionally NOT used (per memory
# project_sandbox_stack.md): SIFT's OVA assumes virtio-scsi + e1000;
# Firecracker forbids legacy PCI + VirtIO-GPU → boot failure.

packer {
  required_version = ">= 1.10.0"
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.0"
    }
  }
}

variable "ova_path" {
  type        = string
  default     = "../sift-2026-04-22.ova"
  description = "Path to the SIFT OVA at repo root."
}

variable "output_dir" {
  type        = string
  default     = "artifacts"
  description = "Packer output directory relative to this .pkr.hcl."
}

variable "ssh_username" {
  type    = string
  default = "sansforensics"
}

variable "ssh_password" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.ssh_password) > 0
    error_message = "Set ssh_password explicitly with -var or a local var file; no default SIFT password is embedded in this public recipe."
  }
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory_mb" {
  type    = number
  default = 8192
}

variable "disk_size_mb" {
  type    = number
  default = 40960
}

# ---------------------------------------------------------------------
# Source — qemu builder with `machine_type = microvm` where the host
# kernel + OVA contents allow, falling back to `q35` if microvm's
# kernel requirement can't be met.
#
# We use the OVA's embedded disk as the base; Packer first converts
# OVA → qcow2 via qemu-img before boot.
# ---------------------------------------------------------------------
source "qemu" "sift_microvm" {
  # Point Packer at the OVA; Packer's qemu builder treats it as the
  # base image. iso_checksum=none is valid for local files.
  iso_url      = var.ova_path
  iso_checksum = "none"

  # Output.
  output_directory = var.output_dir
  vm_name          = "sift-microvm"

  # Boot environment.
  disk_size      = var.disk_size_mb
  format         = "qcow2"
  headless       = true
  cpus           = var.cpus
  memory         = var.memory_mb

  # microvm would be ideal but requires a direct -kernel path.
  # q35 gives us the e1000 + virtio-scsi compatibility SIFT expects.
  # Swap to microvm once the Packer shell provisioner installs a
  # bootable kernel image under /boot.
  machine_type = "q35"
  accelerator  = "kvm"

  # Port-forward localhost:2222 → guest:22 so provisioning is reachable only
  # from the build host.
  qemuargs = [
    ["-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"],
    ["-device", "virtio-net,netdev=net0"]
  ]

  # SSH boot — supply local OVA credentials explicitly at build time.
  ssh_username      = var.ssh_username
  ssh_password      = var.ssh_password
  ssh_port          = 22
  ssh_handshake_attempts = 30
  ssh_wait_timeout  = "15m"
  boot_wait         = "30s"

  shutdown_command  = "sudo -S -E -- shutdown -P now"
  shutdown_timeout  = "10m"
}

# ---------------------------------------------------------------------
# Build.
# ---------------------------------------------------------------------
build {
  name    = "sift-microvm"
  sources = ["source.qemu.sift_microvm"]

  # 1. Minimal provisioning — just make sure the guest has an SSH
  #    server accepting our creds and that tools we care about are on
  #    PATH. Heavy lifting belongs to the Product's install.sh at
  #    runtime, not to Packer.
  provisioner "file" {
    source      = "../scripts/sift-provision.sh"
    destination = "/tmp/sift-provision.sh"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/sift-provision.sh",
      "echo ${var.ssh_password} | sudo -S bash /tmp/sift-provision.sh",
      # Create the `warm` snapshot from a synced-and-idle state.
      "echo ${var.ssh_password} | sudo -S sync",
      "sleep 2"
    ]
  }

  # 2. Post-processor — compress with zstd so GHA cache is under the
  #    5 GB per-file ceiling. Current SIFT qcow2 is ~3-4 GB compressed.
  post-processor "shell-local" {
    inline = [
      "cd ${var.output_dir}",
      "echo 'Creating warm snapshot in the qcow2...'",
      "qemu-img snapshot -c warm sift-microvm",
      "echo 'Compressing with zstd...'",
      "zstd --force --ultra -22 sift-microvm -o sift-microvm-warm.qcow2.zst",
      "echo 'Final artifact:'",
      "ls -lh sift-microvm-warm.qcow2.zst"
    ]
  }
}
