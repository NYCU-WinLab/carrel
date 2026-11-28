#!/usr/bin/env bash
# Turn a Proxmox host into a carrel node (PLAN 8.1, issue #569). It runs the
# idempotent scripts beside it in order, so running it again repairs:
#
#   1. the site file to /etc/carrel/site.json, and storage in node.json
#   2. install-network.py
#   3. on the site's first exit node: bootstrap-platform.py (CT 100, CT 101)
#   4. with --prepared-dir: build-templates.py
#
# The first exit node:  install.sh --site sites/<site>/cluster.json --admin-key KEY.pub
# Another node:         install.sh --site sites/<site>/cluster.json --join <existing node>
#
# --join adds this host to the existing node's Proxmox cluster first (over
# SSH as root, so its key must be trusted there). The host must hold no
# guests. CT 100's config.json and the release (deploy-go.py) stay separate
# steps: see the operator handbook, "Install a site".
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
site="" admin_key="" join="" storage="" prepared="" vmid_base="" images=()
# CARREL_DRY_RUN=1 prints each change instead of making it; checks still run.
run() {
	if [[ ${CARREL_DRY_RUN:-} == 1 ]]; then
		echo "+ $*"
	else
		"$@"
	fi
}
die() {
	echo "install.sh: $*" >&2
	exit 1
}

while (($#)); do
	case $1 in
	--site) site=$2; shift 2 ;;
	--admin-key) admin_key=$2; shift 2 ;;
	--join) join=$2; shift 2 ;;
	--storage) storage=$2; shift 2 ;;
	--prepared-dir) prepared=$2; shift 2 ;;
	--image) images+=(--image "$2"); shift 2 ;;
	--vmid-base) vmid_base=$2; shift 2 ;;
	-h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown argument $1" ;;
	esac
done

[[ -n $site && -f $site ]] || die "--site <sites/<site>/cluster.json> is required"
[[ $(id -u) == 0 || ${CARREL_DRY_RUN:-} == 1 ]] || die "run as root"
command -v pveversion >/dev/null || die "this is not a Proxmox host"

node=$(hostname -s)
# One python3 call reads what the shell needs from the site file, and checks
# this host is in it.
mapfile -t facts < <(python3 - "$site" "$node" "$storage" <<'PY'
import json, re, sys
site, node, storage = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
names = [n["name"] for n in site.get("nodes", [])]
if node not in names:
    sys.exit(f"{node} is not in the site file; add it under nodes first")
exits = site.get("exit_nodes") or []
storage = storage or site.get("storage", "")
if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,62}", storage):
    sys.exit("give --storage, or storage in the site file")
print(exits[0] if exits else "")
print(storage)
PY
) || die "the site file does not fit this host"
first_exit=${facts[0]} storage=${facts[1]}

# node-agent.py takes only a ZFS pool for guests (PLAN 8.2).
type=$(pvesh get "/storage/$storage" --output-format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("type",""))' || true)
[[ $type == zfspool ]] || die "guest storage $storage must be a ZFS pool (zfspool), not '${type:-missing}'"

if [[ $node == "$first_exit" && ! -f /etc/pve/lxc/100.conf ]]; then
	[[ -n $admin_key && -f $admin_key ]] || die "the first exit node needs --admin-key <public key file> for CT 100 and CT 101"
elif [[ $node != "$first_exit" && -z $join && ! -f /etc/pve/corosync.conf ]]; then
	die "this host is not in a cluster: give --join <existing node>"
fi

if [[ -n $join ]]; then
	if [[ -f /etc/pve/corosync.conf ]]; then
		echo "install.sh: already in a cluster, --join skipped"
	else
		if [[ -n $(qm list 2>/dev/null | tail -n +2) || -n $(pct list 2>/dev/null | tail -n +2) ]]; then
			die "a joining host must hold no guests"
		fi
		# pvecm add exits 0 even when it stops early, for example when
		# ssh-copy-id cannot reach root on the existing node, so check the
		# result instead of the exit status.
		run pvecm add "$join" --use_ssh 1
		if [[ ${CARREL_DRY_RUN:-} != 1 && ! -f /etc/pve/corosync.conf ]]; then
			die "pvecm add $join did not join the cluster; root on this host must reach root@$join over SSH without a prompt, host key included"
		fi
	fi
fi

# configure-nodes.py writes the control plane's key line once, into root's
# authorized_keys, which Proxmox shares across the cluster as a link to
# /etc/pve/priv/authorized_keys. A host made from a cloud image before
# Proxmox was installed keeps its own file, and the other nodes never get
# the line.
if [[ ${CARREL_DRY_RUN:-} != 1 && -e /root/.ssh/authorized_keys && $(readlink -f /root/.ssh/authorized_keys) != /etc/pve/priv/authorized_keys ]]; then
	die "/root/.ssh/authorized_keys is not the cluster's shared file: append its lines to /etc/pve/priv/authorized_keys, then link it there (ln -sf /etc/pve/priv/authorized_keys /root/.ssh/authorized_keys)"
fi

# A host without a subscription cannot read the enterprise repositories that
# installing proxmox-ve adds, and every apt-get update after fails. Turn them
# off and read pve-no-subscription instead (from the site's mirror if one is
# already configured).
if ! pvesubscription get 2>/dev/null | grep -q '^status: active'; then
	for f in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.sources; do
		if [[ -f $f ]] && grep -q enterprise.proxmox.com "$f" && ! grep -q '^Enabled: no' "$f"; then
			run sh -c "echo 'Enabled: no' >> '$f'"
		fi
	done
	if ! grep -rqs pve-no-subscription /etc/apt/sources.list.d/ /etc/apt/sources.list; then
		codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
		run sh -c "printf 'Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: %s\nComponents: pve-no-subscription\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n' '$codename' > /etc/apt/sources.list.d/proxmox.sources"
	fi
fi

run install -d -m 755 /etc/carrel
if ! cmp -s "$site" /etc/carrel/site.json; then
	[[ -f /etc/carrel/site.json ]] && run cp /etc/carrel/site.json "/etc/carrel/site.json.$(date +%Y%m%d%H%M%S)"
	run install -m 644 "$site" /etc/carrel/site.json
fi
# Keep the keys install-network.py owns; set only storage.
run python3 -c 'import json, pathlib, sys
p = pathlib.Path("/etc/carrel/node.json")
c = json.loads(p.read_text()) if p.exists() else {}
c["storage"] = sys.argv[1]
p.write_text(json.dumps(c, indent=2) + "\n")' "$storage"

run python3 "$here/install-network.py" --site /etc/carrel/site.json
if [[ $node == "$first_exit" ]]; then
	if [[ -n $admin_key ]]; then
		run python3 "$here/bootstrap-platform.py" --admin-key "$admin_key"
	else
		run python3 "$here/bootstrap-platform.py" --firewall
	fi
fi
if [[ -n $prepared ]]; then
	args=(--prepared-dir "$prepared" "${images[@]}")
	[[ -n $vmid_base ]] && args+=(--vmid-base "$vmid_base")
	run python3 "$here/build-templates.py" "${args[@]}"
fi

echo "install.sh: $node is installed."
if [[ -n $join && $node != "$first_exit" ]]; then
	echo "Next: on $first_exit, run scripts/bootstrap-platform.py --firewall so the infra firewalls admit $node."
	echo "Then on every other node, with the new site file, run scripts/install.sh --site <site file> again:"
	echo "its carrel_tenant_host table drops VXLAN and BGP from any node it does not list, $node included."
fi
if [[ $node == "$first_exit" ]]; then
	echo "Next: write CT 100's /etc/carrel/config.json, then run deploy-go.py --host root@$first_exit from a workstation."
fi
