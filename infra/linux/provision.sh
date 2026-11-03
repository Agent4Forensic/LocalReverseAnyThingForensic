#!/usr/bin/env bash
# provision.sh - one-time setup of the Debian 13 live host for sw-analyst (ADR-0013, docs/runbooks/linux-ventoy.md).
#   sudo sw-mode online   (or before sw-mode exists: network on by hand)
#   sudo infra/linux/provision.sh [--user analyst] [--sw-root /srv/sw-analyst] [--no-desktop] [--no-nvidia]
# What it does: Debian packages only (signed by Debian, no third-party repository), Docker Engine (docker.io) with its data
# on SWDATA, the NVIDIA driver from Debian non-free, zram swap, the minimal Xfce desktop, the platform user, sw-mode,
# sw-share, the offline boot default and the sudoers rule. It never formats, partitions or mounts a disk: SWDATA and
# fstab follow the runbook by hand, because a wrong device name there destroys data.
# Idempotent: a second run changes nothing that is already in place.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME=analyst
SW_ROOT=/srv/sw-analyst
DESKTOP=1
NVIDIA=1
while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_NAME="$2"; shift 2 ;;
    --sw-root) SW_ROOT="$2"; shift 2 ;;
    --no-desktop) DESKTOP=0; shift ;;
    --no-nvidia) NVIDIA=0; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "invalid user name" >&2; exit 2; }
[[ "$SW_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "invalid --sw-root" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = debian ] || echo "WARNING: written for Debian 13, found ${PRETTY_NAME:-unknown}" >&2
step() { echo; echo "== $*"; }

step "apt sources: main contrib non-free non-free-firmware"
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  sed -i -E 's/^Components:.*/Components: main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources
elif [ -f /etc/apt/sources.list ]; then
  sed -i -E '/^deb /{/non-free-firmware/!s/ main( |$)/ main contrib non-free non-free-firmware\1/}' /etc/apt/sources.list
fi
apt-get update

step "base packages"
apt-get install -y --no-install-recommends \
  python3 python3-venv git ca-certificates curl zstd \
  nftables rfkill network-manager iproute2 cryptsetup exfatprogs util-linux \
  docker.io systemd-zram-generator dbus-user-session

if [ "$DESKTOP" = 1 ]; then
  step "minimal desktop: Xfce, terminal, file manager, Firefox ESR"
  apt-get install -y --no-install-recommends \
    xfce4 xfce4-terminal thunar lightdm lightdm-gtk-greeter firefox-esr fonts-dejavu xdg-utils
fi

if [ "$NVIDIA" = 1 ]; then
  step "NVIDIA driver (Debian non-free, DKMS against the running kernel)"
  apt-get install -y linux-headers-amd64 nvidia-driver firmware-misc-nonfree nvidia-smi || \
    echo "WARNING: NVIDIA packages failed; see docs/runbooks/linux-ventoy.md (driver series >= 570 needed for RTX 50)" >&2
  echo "Version check after the reboot: nvidia-smi --query-gpu=driver_version --format=csv"
  echo "RTX 50 (Blackwell) needs series 570 or newer with the open kernel modules. If Debian ships an older one, follow"
  echo "the runbook section 'NVIDIA-Treiber': it needs a review before any third-party repository is added (CLAUDE.md, rule 8)."
fi

step "zram swap (2 GB): a model never pages out to the USB disk"
cat > /etc/systemd/zram-generator.conf <<'EOF'
[zram0]
zram-size = 2048
compression-algorithm = zstd
EOF
for s in $(swapon --show=NAME --noheadings | grep -v zram || true); do swapoff "$s" || true; done

step "platform user $USER_NAME"
id "$USER_NAME" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$USER_NAME"
usermod -aG docker "$USER_NAME"
echo "NOTE: members of the docker group are root-equivalent on this host (ADR-0013, risk accepted with F6)."
loginctl enable-linger "$USER_NAME" || true   # user systemd manager for sw-analyst.slice

step "Docker Engine: data on $SW_ROOT/docker, no-new-privileges, no inter-container traffic"
install -d -m 0755 /etc/docker
sed "s#/srv/sw-analyst#$SW_ROOT#" "$HERE/daemon.json" > /etc/docker/daemon.json
if mountpoint -q "$SW_ROOT" || [ -d "$SW_ROOT" ]; then
  install -d -m 0710 "$SW_ROOT/docker"
else
  echo "WARNING: $SW_ROOT is not there yet; Docker starts after SWDATA is mounted (runbook 7.3)." >&2
fi
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/sw-analyst.conf <<EOF
[Unit]
RequiresMountsFor=$SW_ROOT
EOF

step "sw-mode, sw-share, offline boot default, sudoers"
install -d -m 0755 /etc/sw-analyst
install -m 0644 "$HERE/nftables-offline.nft" /etc/sw-analyst/nftables-offline.nft
[ -f /etc/sw-analyst/share.conf ] || install -m 0644 "$HERE/share.conf.example" /etc/sw-analyst/share.conf
sed -i "s/^SHARE_USER=.*/SHARE_USER=$USER_NAME/" /etc/sw-analyst/share.conf
install -m 0755 "$HERE/sw-mode" /usr/local/sbin/sw-mode
install -m 0755 "$HERE/sw-share" /usr/local/sbin/sw-share
install -m 0644 "$HERE/sw-offline.service" /etc/systemd/system/sw-offline.service
tmp="$(mktemp)"
sed "s/^analyst /$USER_NAME /" "$HERE/sudoers-sw-analyst" > "$tmp"
visudo -cf "$tmp" && install -m 0440 "$tmp" /etc/sudoers.d/sw-analyst
rm -f "$tmp"

step "services"
systemctl daemon-reload
systemctl enable sw-offline.service
systemctl enable docker.service
systemctl disable --now ssh.service 2>/dev/null || true   # nothing listens from outside

step "done"
echo "Next (runbook 7.3): SWDATA in /etc/fstab (and /etc/crypttab), reboot, nvidia-smi, then as $USER_NAME:"
echo "  cd $SW_ROOT/repo && SW_ROOT=$SW_ROOT scripts/start.sh --setup && sudo sw-mode offline && scripts/start.sh"
echo "Set the share UUID in /etc/sw-analyst/share.conf (lsblk -f)."
