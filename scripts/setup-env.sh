#!/usr/bin/env bash
# One-time environment setup for howdy-passkey-bridge.
# Target: CachyOS / Arch. Run when you're at the machine (Howdy prompts for sudo).
#
# Isolation policy:
#   - SYSTEM (unavoidable): go toolchain, usbip, tpm2 libs, vhci-hcd kernel module,
#     pamtester. A compiler, kernel-facing C libs, and a kernel module cannot live
#     in a venv.
#   - PROJECT-LOCAL (isolated): Go module/build cache + binaries (./.go, ./bin).
#     See scripts/env.sh.
#
# Privilege model: the bridge runs fully unprivileged. usbip needs to write the
# vhci attach/detach sysfs controls; instead of sudo we create a "usbip" group,
# add you to it, and a udev rule grants that group write access. No sudoers entry.
set -euo pipefail

HPB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HPB_ROOT"

# ---------------------------------------------------------------------------
# Preflight: things this script does NOT install for you.
# Howdy itself is distro-specific and enrollment is personal/interactive, so we
# detect rather than install. Hardware (TPM/IR) is checked and warned about.
# ---------------------------------------------------------------------------
echo "==> [preflight] Checking Howdy"
if ! command -v howdy >/dev/null 2>&1 && ! ls /lib/security/howdy /usr/lib/security/howdy >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: Howdy not found. Install it first (distro-specific):
  Arch:   yay -S howdy-git        (the original 'howdy' AUR pkg is broken on modern Arch)
  Ubuntu: sudo add-apt-repository ppa:boltgolt/howdy && sudo apt install howdy
  source: https://github.com/boltgolt/howdy
Then enroll your face:  sudo howdy add
EOF
    exit 1
fi

# Warn if no face is enrolled yet (best-effort; output format varies by version).
if command -v howdy >/dev/null 2>&1 && ! sudo howdy list 2>/dev/null | grep -qiE '^[0-9]|model'; then
    echo "WARN: no enrolled Howdy face detected. Run: sudo howdy add" >&2
fi

echo "==> [preflight] Ensuring /etc/pam.d/howdy-only (face-only PAM stack)"
if [ ! -f /etc/pam.d/howdy-only ]; then
    # Copy the exact howdy auth line from whatever service already uses it, so the
    # module path is correct for this distro. Fall back to the common howdy-git path.
    HOWDY_LINE="$(grep -rhE 'pam_(python|howdy)' /etc/pam.d/ 2>/dev/null | grep -i howdy | head -1)"
    if [ -z "$HOWDY_LINE" ]; then
        if [ -f /lib/security/howdy/pam.py ]; then
            HOWDY_LINE="auth sufficient pam_python.so /lib/security/howdy/pam.py"
        elif [ -f /usr/lib/security/howdy/pam.py ]; then
            HOWDY_LINE="auth sufficient pam_python.so /usr/lib/security/howdy/pam.py"
        else
            echo "ERROR: cannot locate Howdy PAM module to build howdy-only. Create /etc/pam.d/howdy-only manually." >&2
            exit 1
        fi
    fi
    printf '#%%PAM-1.0\n# face-only stack for howdy-passkey-bridge user-verification\n%s\nauth required pam_deny.so\n' \
        "$HOWDY_LINE" | sudo tee /etc/pam.d/howdy-only >/dev/null
    echo "  created /etc/pam.d/howdy-only"
else
    echo "  already present"
fi

echo "==> [preflight] Hardware checks (warn-only)"
[ -e /dev/tpmrm0 ] && echo "  TPM 2.0: present" || \
    echo "  WARN: no /dev/tpmrm0 - keys will fall back to an encrypted file vault (weaker, see docs/security.md)"
echo "  NOTE: liveness depends on an IR depth camera. RGB-only webcams are photo/screen-spoofable - do not trust this for real accounts without IR."

echo "==> [system] Installing toolchain + kernel-facing deps (pacman)"
# NOTE: Arch/pacman only. On Debian/Ubuntu the equivalents are roughly:
#   sudo apt install golang gcc usbip libtss2-dev tpm2-tools pamtester
# go,gcc    : build the Go fork (cgo needs a C compiler for the tpm2 binding)
# usbip     : attach the virtual USB authenticator to localhost
# tpm2-*    : seal passkey keys to the TPM (tss = lib for cgo, tools = CLI for debugging)
# pamtester : the approver runs `pamtester howdy-only <user> authenticate` to gate
#             each WebAuthn ceremony on a live Howdy face match
sudo pacman -S --needed --noconfirm go gcc usbip tpm2-tss tpm2-tools pamtester

echo "==> [system] Loading vhci-hcd (virtual USB host controller)"
sudo modprobe vhci-hcd
echo "vhci-hcd" | sudo tee /etc/modules-load.d/vhci-hcd.conf >/dev/null   # persist across reboot

echo "==> [system] usbip group + udev rule (unprivileged attach, no sudo)"
# Create the group, add the CURRENT user (never hardcoded), install the udev rule
# that hands the group write access to the vhci attach/detach controls, and apply
# it to the already-loaded device so no reboot is needed. Single sudo block.
TARGET_USER="$(id -un)"
sudo bash -c "
set -e
getent group usbip >/dev/null || groupadd -r usbip
usermod -aG usbip '$TARGET_USER'
install -m 0644 '$HPB_ROOT/scripts/70-howdy-passkey-vhci.rules' /etc/udev/rules.d/70-howdy-passkey-vhci.rules
udevadm control --reload
if [ -d /sys/devices/platform/vhci_hcd.0 ]; then
    chgrp usbip /sys/devices/platform/vhci_hcd.0/attach /sys/devices/platform/vhci_hcd.0/detach
    chmod 0660 /sys/devices/platform/vhci_hcd.0/attach /sys/devices/platform/vhci_hcd.0/detach
fi
"
echo "  NOTE: log out and back in (or use 'sg usbip') for the new group to take effect."

echo "==> [project] Creating local Go cache dirs"
mkdir -p "$HPB_ROOT/.go" "$HPB_ROOT/bin"

echo "==> Verifying"
# shellcheck disable=SC1091
. "$HPB_ROOT/scripts/env.sh"
go version
usbip version 2>/dev/null || true
command -v pamtester >/dev/null && echo "pamtester: present" || echo "pamtester: MISSING"
{ lsmod | grep -q vhci_hcd || [ -d /sys/devices/platform/vhci_hcd.0 ]; } \
    && echo "vhci-hcd: loaded" || echo "vhci-hcd: NOT loaded (check dmesg)"
test -e /dev/tpmrm0 && echo "tpm: /dev/tpmrm0 present" || echo "tpm: MISSING"
test -f /etc/pam.d/howdy-only && echo "pam: howdy-only present" || echo "pam: howdy-only MISSING"
id -nG "$(id -un)" | grep -qw usbip \
    && echo "group: in 'usbip' (active)" \
    || echo "group: 'usbip' set but not active in this session yet - re-login or use 'sg usbip'"

echo
echo "==> Done. Before working in this repo, run:  . scripts/env.sh"
echo "    Then start the bridge:  ./bin/howdy-bridge --passphrase <pass>"
