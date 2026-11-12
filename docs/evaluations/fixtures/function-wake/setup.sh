#!/bin/bash
# Prepare Firecracker, a guest kernel, and a tiny busybox rootfs that serves HTTP.
set -euo pipefail
W=/opt/fnlab; sudo mkdir -p $W; sudo chown "$USER" $W; cd $W
ARCH=x86_64

sudo apt-get update -qq >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq busybox-static e2fsprogs iproute2 >/dev/null

# Firecracker release binary
if [ ! -x firecracker ]; then
  TAG=$(curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"])')
  curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/$TAG/firecracker-$TAG-$ARCH.tgz" | tar xz
  cp "release-$TAG-$ARCH/firecracker-$TAG-$ARCH" firecracker
  echo "$TAG" > fc.version
fi

# Guest kernel from the Firecracker CI bucket (newest listed)
if [ ! -f vmlinux ]; then
  KEY=firecracker-ci/v1.15/x86_64/vmlinux-6.1.155  # newest kernel the CI bucket publishes
  curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/$KEY" -o vmlinux
  echo "$KEY" > kernel.version
fi

# Rootfs: static busybox as init, httpd on port 80
rm -rf root rootfs.ext4; mkdir -p root/{bin,proc,sys,dev,www,tmp}
cp /bin/busybox root/bin/busybox
echo ok > root/www/index.html
cat > root/init <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox ip addr add 172.16.0.2/30 dev eth0
/bin/busybox ip link set eth0 up
exec /bin/busybox httpd -f -p 80 -h /www
EOF
chmod +x root/init
truncate -s 16M rootfs.ext4
/usr/sbin/mkfs.ext4 -q -d root rootfs.ext4

# Persistent tap with a static neighbour entry, so no ARP delay skews timing
sudo ip link del tap0 2>/dev/null || true
sudo ip tuntap add dev tap0 mode tap
sudo ip addr add 172.16.0.1/30 dev tap0
sudo ip link set tap0 up
sudo ip neigh replace 172.16.0.2 lladdr 06:00:AC:10:00:02 dev tap0 nud permanent

cat fc.version kernel.version; ls -la $W | grep -E "firecracker$|vmlinux|rootfs"
