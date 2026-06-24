#!/usr/bin/env bash
# One-time environment setup for howdy-passkey-bridge.
# Target: CachyOS / Arch. Run when you're at the machine (Howdy prompts for sudo).
#
# Isolation policy:
#   - SYSTEM (unavoidable): go toolchain, usbip, tpm2 libs, vhci-hcd kernel module.
#     A compiler, kernel-facing C libs, and a kernel module cannot live in a venv.
#   - PROJECT-LOCAL (isolated): Go module/build cache + binaries (./.go, ./bin)
#     and a Python venv (./.venv). See scripts/env.sh.
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
    echo "  WARN: no /dev/tpmrm0 — keys will fall back to an encrypted file vault (weaker, see docs/security.md)"
echo "  NOTE: liveness depends on an IR depth camera. RGB-only webcams are photo/screen-spoofable — do not trust this for real accounts without IR."

echo "==> [system] Installing toolchain + kernel-facing deps (pacman)"
# NOTE: Arch/pacman only. On Debian/Ubuntu the equivalents are roughly:
#   sudo apt install golang gcc usbip libtss2-dev tpm2-tools && pipx install uv
# go,gcc  : build the Go fork (cgo needs a C compiler for the tpm2 binding)
# usbip   : attach the virtual USB authenticator to localhost
# tpm2-*  : seal passkey keys to the TPM (tss = lib for cgo, tools = CLI for debugging)
# uv      : project-local Python venvs (PEP 668 — never system pip on this box)
sudo pacman -S --needed --noconfirm go gcc usbip tpm2-tss tpm2-tools uv

echo "==> [system] Loading vhci-hcd (virtual USB host controller)"
sudo modprobe vhci-hcd
echo "vhci-hcd" | sudo tee /etc/modules-load.d/vhci-hcd.conf >/dev/null   # persist across reboot

echo "==> [project] Creating local Go cache dirs"
mkdir -p "$HPB_ROOT/.go" "$HPB_ROOT/bin"

echo "==> [project] Creating Python venv (uv) for the PAM helper prototype"
uv venv "$HPB_ROOT/.venv"
# python-pam: authenticate against the /etc/pam.d/howdy-only service from Python
VIRTUAL_ENV="$HPB_ROOT/.venv" uv pip install python-pam

echo "==> Verifying"
# shellcheck disable=SC1091
. "$HPB_ROOT/scripts/env.sh"
go version
usbip version 2>/dev/null || true
{ lsmod | grep -q vhci_hcd || [ -d /sys/devices/platform/vhci_hcd.0 ]; } \
    && echo "vhci-hcd: loaded" || echo "vhci-hcd: NOT loaded (check dmesg)"
test -e /dev/tpmrm0 && echo "tpm: /dev/tpmrm0 present" || echo "tpm: MISSING"
test -f /etc/pam.d/howdy-only && echo "pam: howdy-only present" || echo "pam: howdy-only MISSING"

echo
echo "==> Done. Before working in this repo, run:  . scripts/env.sh"
