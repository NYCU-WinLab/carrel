#!/usr/bin/env python3
"""Install PVE inside the dedicated carrel-stg01 VM, with a guarded data disk.

Copy the public Proxmox archive keyring from the existing PVE host and pass it
with --archive-keyring. Only the disk whose serial is carrel-staging-data may
be initialized. A reboot is required after the first run; it is not automatic.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

MARKER = "# Managed by carrel staging bootstrap.\n"


def run(*args, capture=False, timeout=120, input=None):
    result = subprocess.run(args, check=True, text=True, input=input, timeout=timeout,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def write(filename, content, changes):
    path = Path(filename)
    if path.exists() and path.read_text() == content:
        return
    if path.exists() and not path.with_name(path.name + ".before-carrel").exists():
        shutil.copy2(path, path.with_name(path.name + ".before-carrel"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    path.write_text(content)
    path.chmod(0o644)
    changes.append(filename)


def active_package(package):
    result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.returncode == 0 and result.stdout == "installed"


def disable_enterprise_repositories(changes):
    for filename in ("/etc/apt/sources.list.d/pve-enterprise.sources", "/etc/apt/sources.list.d/ceph.sources"):
        path = Path(filename)
        if path.exists() and "enterprise.proxmox.com" in path.read_text() and "Enabled: no" not in path.read_text():
            write(filename, path.read_text().rstrip() + "\nEnabled: no\n", changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-keyring", type=Path, required=True)
    parser.add_argument("--admin-key", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or run("hostname", "-s", capture=True) != "carrel-stg01":
        parser.error("run only as root on carrel-stg01")
    if run("systemd-detect-virt", capture=True) != "kvm":
        parser.error("refusing to run outside the nested staging VM")
    if 'VERSION_CODENAME=trixie' not in Path("/etc/os-release").read_text():
        parser.error("Debian trixie required")
    links = json.loads(run("ip", "-j", "-4", "address", "show", capture=True))
    if not any(a.get("local") == "172.31.255.2" for link in links for a in link["addr_info"]):
        parser.error("expected staging management address is missing")
    devices = json.loads(run("lsblk", "-J", "-o", "PATH,SERIAL,TYPE,FSTYPE", capture=True))["blockdevices"]
    disks = [d for d in devices if d.get("serial") == "carrel-staging-data" and d["type"] == "disk"]
    if len(disks) != 1:
        parser.error("exactly one dedicated staging data disk is required")
    disk = disks[0]
    if disk.get("fstype") not in (None, "", "LVM2_member") or disk.get("children") and disk.get("fstype") != "LVM2_member":
        parser.error("staging data disk contains an unexpected filesystem or partitions")
    keyring = args.archive_keyring.read_bytes()
    if not keyring:
        parser.error("empty Proxmox archive keyring")
    admin_key = args.admin_key.read_text().strip()
    if not admin_key.startswith("ssh-ed25519 ") or "\n" in admin_key:
        parser.error("provide one administrator ed25519 public key")
    run("ssh-keygen", "-l", "-f", str(args.admin_key), capture=True)
    root_source = run("findmnt", "-n", "-o", "SOURCE", "/", capture=True)
    root_disk = "/dev/" + run("lsblk", "-ndo", "PKNAME", root_source, capture=True)
    if run("lsblk", "-dn", "-o", "SERIAL", root_disk, capture=True) != "drive-scsi0" or root_disk == disk["path"]:
        parser.error("unexpected staging boot disk")
    packages = ("proxmox-ve", "proxmox-default-kernel", "grub-pc", "postfix", "open-iscsi", "chrony", "ifupdown2", "qemu-guest-agent")
    missing = [p for p in packages if not active_package(p)]
    if not args.apply:
        print(json.dumps({"node": "carrel-stg01", "data_disk": disk["path"], "missing_packages": missing,
                          "network": "172.31.255.2/24 on vmbr0 via eth0", "storage": "local-lvm"}, indent=2))
        return
    cloud_disabled = Path("/etc/cloud/cloud-init.disabled")
    if not cloud_disabled.exists() or cloud_disabled.read_text() != MARKER:
        cloud_result = subprocess.run(["cloud-init", "status", "--wait", "--format", "json"],
                                      text=True, stdout=subprocess.PIPE, timeout=600)
        cloud_status = json.loads(cloud_result.stdout)
        # PVE 9.1 emits the deprecated scalar 'user' field. Cloud-init reports
        # exit 2 for it even when all stages succeeded; actual boot errors fail.
        recoverable = cloud_status.get("recoverable_errors", {})
        if cloud_result.returncode not in (0, 2) or cloud_status.get("status") != "done" or cloud_status.get("errors") or set(recoverable) - {"DEPRECATED"}:
            raise RuntimeError("cloud-init did not finish cleanly: " + cloud_result.stdout)
        if recoverable:
            print("cloud-init completed with PVE user-field deprecation warnings", flush=True)
    changes = []
    # PVE replaces root's authorized_keys with a pmxcfs-managed symlink. Keep
    # the staging administrator's public key independently of that bootstrap.
    write("/etc/ssh/carrel-staging-admin.pub", admin_key + "\n", changes)
    write("/etc/ssh/sshd_config.d/60-carrel-staging-admin.conf", MARKER + """Match User root
    AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/carrel-staging-admin.pub
Match all
""", changes)
    run("sshd", "-t")
    if any(p.startswith("/etc/ssh/") for p in changes):
        run("systemctl", "reload", "ssh.service")
    target_keyring = Path("/usr/share/keyrings/proxmox-archive-keyring.gpg")
    if not target_keyring.exists() or target_keyring.read_bytes() != keyring:
        target_keyring.write_bytes(keyring)
        target_keyring.chmod(0o644)
        changes.append("Proxmox archive keyring")
    write("/etc/apt/sources.list.d/carrel-pve.sources", MARKER + """Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
""", changes)
    # PVE resolves its node name before creating pmxcfs and node certificates.
    write("/etc/hosts", MARKER + """127.0.0.1 localhost
172.31.255.2 carrel-stg01.staging.internal carrel-stg01
::1 localhost ip6-localhost ip6-loopback
""", changes)
    write("/etc/cloud/cloud.cfg.d/99-carrel-staging.cfg", MARKER + """preserve_hostname: true
manage_etc_hosts: false
network:
  config: disabled
""", changes)
    write("/etc/default/grub.d/99-carrel-staging.cfg", MARKER + 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} net.ifnames=0"\n', changes)
    disable_enterprise_repositories(changes)
    if missing:
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
        run("debconf-set-selections", input="postfix postfix/mailname string carrel-stg01.staging.internal\npostfix postfix/main_mailer_type select Local only\n"
            + f"grub-pc grub-pc/install_devices multiselect {root_disk}\ngrub-pc grub-pc/install_devices_disks_changed multiselect {root_disk}\n"
            + "grub-pc grub-pc/install_devices_empty boolean false\ngrub-pc grub-pc/install_devices_failed_upgrade boolean false\n")
        # The vendor's no-subscription repository uses HTTP; APT verifies its
        # signed InRelease and package hashes with the copied archive keyring.
        run("apt-get", "-o", "APT::Update::Error-Mode=any", "update", timeout=900)
        run("apt-get", "install", "-y", *missing, timeout=2700)
        changes.append("PVE packages")
    if "/etc/default/grub.d/99-carrel-staging.cfg" in changes:
        run("update-grub")
    # Package defaults may add enterprise repositories; this guest has no subscription.
    disable_enterprise_repositories(changes)
    interfaces = MARKER + """auto lo
iface lo inet loopback

iface eth0 inet manual

auto vmbr0
iface vmbr0 inet static
    address 172.31.255.2/24
    gateway 172.31.255.1
    bridge-ports eth0
    bridge-stp off
    bridge-fd 0

source /etc/network/interfaces.d/*
"""
    write("/etc/network/interfaces", interfaces, changes)
    if Path("/etc/network/interfaces.new").exists():
        # pvenetcommit would otherwise replace our bridge at the next boot.
        write("/etc/network/interfaces.new", interfaces, changes)
    Path("/etc/network/interfaces.d").mkdir(exist_ok=True)
    write("/etc/resolv.conf", MARKER + "nameserver 1.1.1.1\nsearch staging.internal\n", changes)
    netplan = Path("/etc/netplan/50-cloud-init.yaml")
    if netplan.exists():
        # Netplan's generator would re-enable networkd at boot and put the
        # address on eth0 as well as vmbr0. Retain its old configuration only
        # as a backup after switching this dedicated guest to ifupdown2.
        if "172.31.255.2/24" not in netplan.read_text():
            raise RuntimeError("unexpected cloud-init network configuration")
        backup = netplan.with_name(netplan.name + ".before-carrel")
        if not backup.exists():
            shutil.copy2(netplan, backup)
        netplan.unlink()
        changes.append("retired cloud-init netplan configuration")
    for service in ("systemd-networkd.service", "systemd-networkd.socket", "systemd-resolved.service"):
        enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", service]).returncode == 0
        if enabled:
            run("systemctl", "disable", service)
            changes.append("disabled " + service + " at next boot")
    for service in ("networking.service", "qemu-guest-agent.service"):
        if subprocess.run(["systemctl", "is-enabled", "--quiet", service]).returncode != 0:
            run("systemctl", "enable", service)
            changes.append("enabled " + service)
    cluster_restarted = False
    for service in ("pve-cluster", "pvedaemon", "pveproxy", "pvestatd", "pvescheduler", "pve-firewall", "pve-ha-lrm", "pve-ha-crm", "qemu-guest-agent"):
        if subprocess.run(["systemctl", "is-active", "--quiet", service]).returncode != 0:
            run("systemctl", "reset-failed", service)
            run("systemctl", "start", service)
            changes.append("started " + service)
            cluster_restarted |= service == "pve-cluster"
    if cluster_restarted:
        run("systemctl", "restart", "pveproxy")
    # Only initialize a signature-free disk. Never use --force, wipefs, or vgremove.
    if disk.get("fstype") != "LVM2_member":
        signatures = json.loads(run("wipefs", "--json", "--no-act", disk["path"], capture=True))
        if signatures.get("signatures"):
            raise RuntimeError("refusing to initialize a data disk with signatures")
        if subprocess.run(["vgs", "pve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError("an unexpected pve volume group already exists")
        run("pvcreate", disk["path"])
        run("vgcreate", "pve", disk["path"])
        changes.append("staging data volume group")
    pv_rows = json.loads(run("pvs", "--reportformat", "json", "-o", "pv_name,vg_name", capture=True))["report"][0]["pv"]
    members = [row["pv_name"] for row in pv_rows if row["vg_name"] == "pve"]
    if members != [disk["path"]]:
        raise RuntimeError("pve must contain only the dedicated staging disk")
    if subprocess.run(["lvs", "pve/data"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        run("lvcreate", "--type", "thin-pool", "-L", "150G", "-n", "data", "pve")
        changes.append("staging thin pool")
    storages = json.loads(run("pvesh", "get", "/storage", "--output-format", "json", capture=True))
    storage = next((s for s in storages if s["storage"] == "local-lvm"), None)
    if storage:
        if storage["type"] != "lvmthin" or storage.get("vgname") != "pve" or storage.get("thinpool") != "data":
            raise RuntimeError("unexpected local-lvm storage definition")
    else:
        run("pvesm", "add", "lvmthin", "local-lvm", "--vgname", "pve", "--thinpool", "data", "--content", "images,rootdir")
        changes.append("local-lvm storage registration")
    if run("timedatectl", "show", "--property=Timezone", "--value", capture=True) != "Asia/Taipei":
        run("timedatectl", "set-timezone", "Asia/Taipei")
        changes.append("timezone")
    # This guest is now a PVE host, not a member's cloud-init VM. NoCloud user
    # data has higher priority than cloud.cfg and otherwise rewrites /etc/hosts
    # to a loopback node address at every boot, breaking pmxcfs and SSH trust.
    write(str(cloud_disabled), MARKER, changes)
    reboot_required = not run("uname", "-r", capture=True).endswith("-pve") or not any(l["ifname"] == "vmbr0" for l in links)
    print(json.dumps({"changed": changes, "reboot_required": reboot_required, "storage": "local-lvm"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"nested PVE install failed: {exc}", file=sys.stderr)
        sys.exit(1)
