package carrel

func resizeCompletion(m, before, requested D) D {
	r := D{"allocated": requested, "guest_resources": "unverified", "cpu_memory": "unchanged", "guest_filesystem": "unchanged"}
	if !equal(pick(before, "cpu", "memory_mb"), pick(requested, "cpu", "memory_mb")) {
		r["cpu_memory"] = "verify_in_guest; a VM shutdown/start may be required"
	}
	if num(requested["disk_gb"]) > num(before["disk_gb"]) {
		r["guest_filesystem"] = "unverified"
		r["next_action"] = "verify_guest_capacity_over_ssh"
		r["inspect"] = "findmnt -no SOURCE,FSTYPE /; lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS; df -h /"
		if m["kind"] == "vm" {
			r["owner_action"] = "Inspect the actual root device first. For ext4 on /dev/sdaN with a larger disk, use its observed partition number N: sudo growpart /dev/sda N, then sudo resize2fs /dev/sdaN and df -h /. Prepared Debian can use sda3 and Ubuntu sda1; do not assume a partition number. Inspect other filesystems/layouts before choosing commands. Do not reboot without authorization."
		} else {
			r["owner_action"] = "PVE resizes the CT root volume. Verify the filesystem size over SSH before reporting guest capacity as complete."
		}
	}
	return r
}
