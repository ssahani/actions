# Actions

This repository is a suite of reusable Tinkerbell Actions that are used to compose Tinkerbell Workflows.

| Name | Description |
| --- | --- |
| [archive2disk](/archive2disk/)    | Write archives to a block device |
| [cexec](/cexec/)                  | chroot and execute binaries |
| [grub2disk](/grub2disk/)          | Write grub configs to a block device |
| [image2disk](/image2disk/)        | Write images to a block device |
| [kexec](/kexec/)                  | kexec to a Linux Kernel |
| [oci2disk](/oci2disk/)            | Stream OCI compliant images from a registry and write to a block device |
| [qemuimg2disk](/qemuimg2disk/)    | Stream images and write to a block device |
| [rootio](/rootio/)                | Manage disks (partition, format etc)
| [slurp](/slurp/)                  | Stream a block device to a remote server |
| [syslinux](/syslinux/)            | Install the syslinux bootloader to a block device |
| [writefile](/writefile/)          | This container writes a file to a mounted, LUKS-encrypted root filesystem using a keyfile stored on an unencrypted boot partition. |

# 🛡️ Ubuntu Disk Encryptor for Tinkerbell Bare Metal Provisioning

## 📌 Problem

The official [Image Builder](https://github.com/kubernetes-sigs/image-builder) project **does not support LUKS encryption** for Ubuntu raw disk images by default. This is a critical limitation when provisioning **secure, encrypted bare metal systems** in cloud-native environments like [Tinkerbell](https://tinkerbell.org/).

Additionally, Tinkerbell's official actions like [`writefile`](https://github.com/tinkerbell/actions/tree/main/writefile) **do not support writing into LUKS-encrypted root partitions**, which means injecting configuration (e.g. `cloud-init`, SSH keys, Netplan) fails unless the volume is manually decrypted and mounted beforehand.

---

## ✅ Solution

To address this, we developed two components:

### 🔐 [`encrypt-ubuntu-image.sh`](https://github.com/ssahani/ubuntu-disk-encryptor/blob/main/encrypt-ubuntu-image.sh)

A standalone Bash script to convert an unencrypted Ubuntu 22.04+ raw disk image into a **LUKS2-encrypted** image with:

- ✅ Encrypted root partition (`/`) using LUKS2
- ✅ Unencrypted EFI and `/boot` partitions
- ✅ Keyfile (`/boot/root_crypt.key`) stored in `/boot` and backed up to local disk
- ✅ GRUB, initramfs, `fstab`, and `crypttab` updates in a chrooted environment
- ✅ Root partition auto-resized (+2GB by default)
- ✅ Full debug logging and safe error handling

> **Note**: The `/boot` partition contains the unlock key. Use TPM2, SecureBoot, or other physical security measures to protect it.

---

### 🧩 [`writefile` with LUKS Support](https://github.com/ssahani/actions/tree/main/writefile)

A custom `writefile` action for Tinkerbell that:

- ✅ Unlocks the LUKS-encrypted root partition using `/boot/root_crypt.key`
- ✅ Mounts the decrypted volume at `/mnt/root`
- ✅ Writes arbitrary files (e.g., `cloud-init`, `netplan`, `authorized_keys`) into the mounted filesystem
- ✅ Drop-in replacement for the original `writefile` action

---

## 🧪 Use Case: Tinkerbell + EKS Anywhere

This toolchain is especially useful for provisioning **encrypted Ubuntu nodes** with [EKS Anywhere](https://anywhere.eks.amazonaws.com/) using [Tinkerbell workflows](https://anywhere.eks.amazonaws.com/docs/reference/tinkerbell/).

You can:

1. Stream a **LUKS-encrypted Ubuntu image**
2. Unlock the root partition via keyfile in `/boot`
3. Inject configuration (cloud-init, kubeadm, etc.)
4. Reboot into a **secure, Kubernetes-ready** node

---

## 📦 Example Workflow Snippet

```yaml
tasks:
  - name: install-encrypted-ubuntu
    worker: '{{.device_1}}'
    actions:
      - name: image2disk
        image: quay.io/tinkerbell-actions/image2disk
        ...
      - name: unlock-and-configure
        image: quay.io/ssahani/writefile
        ...
      - name: reboot
        image: public.ecr.aws/tinkerbell-actions/reboot
