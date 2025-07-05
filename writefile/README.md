```
quay.io/ssahani/writefile:latest
```

writefile Tinkerbell Action

This container writes a file (e.g., a Netplan config) to a mounted, LUKS-encrypted root filesystem using a keyfile stored on an unencrypted boot partition.

It is designed to be used in Tinkerbell workflows for provisioning Ubuntu machines with encrypted root filesystems.

⸻

🔧 Purpose

This action:
	1.	Mounts the unencrypted boot partition (e.g., /dev/sda2).
	2.	Unlocks the LUKS root partition (e.g., /dev/sda3) using a keyfile stored in /boot/root_crypt.key.
	3.	Mounts the unlocked root filesystem.
	4.	Writes a file (such as Netplan config) to the mounted root filesystem with correct permissions and ownership.
	5.	Verifies that the file was correctly written.

```yaml
actions:
- name: write-netplan
  image: quay.io/ssahani/writefile:latest
  pid: host
  privileged: true
  timeout: 90
  environment:
    DEST_DISK: /dev/sda3               # LUKS-encrypted root partition
    BOOT_DISK: /dev/sda2               # Unencrypted /boot containing root_crypt.key
    BOOT_FS_TYPE: ext4                 # Filesystem type of /boot
    ROOT_FS_TYPE: ext4                 # Filesystem type of root
    DEST_PATH: /etc/netplan/config.yaml
    CONTENTS: |
      network:
        version: 2
        ethernets:
          enp1s0:
            dhcp4: false
            addresses:
              - 192.168.1.100/24
            gateway4: 192.168.1.1
            nameservers:
              addresses: [8.8.8.8, 1.1.1.1]
    DIR_MODE: "0755"
    FILE_MODE: "0644"
    UID: "0"
    GID: "0"
```
