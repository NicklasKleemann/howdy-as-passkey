#!/usr/bin/env bash
# Install howdy-passkey-bridge as a systemd user service (autostart at login).
# Run after setup-env.sh. No sudo. Prompts you for the vault passphrase.
set -euo pipefail

HPB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$HOME/.config/howdy-passkey-bridge"
BIN="$HOME/.local/bin/howdy-bridge"
UNIT_DIR="$HOME/.config/systemd/user"

echo "==> building"
# shellcheck disable=SC1091
. "$HPB_ROOT/scripts/env.sh"
( cd "$HPB_ROOT/src/virtual-fido" && go build -o "$HPB_ROOT/bin/howdy-bridge" ./cmd/howdy-bridge )

echo "==> installing binary -> $BIN"
mkdir -p "$HOME/.local/bin" "$CONF" "$UNIT_DIR"
install -m 0755 "$HPB_ROOT/bin/howdy-bridge" "$BIN"

echo "==> passphrase env file -> $CONF/passphrase.env (0600)"
if [ ! -f "$CONF/passphrase.env" ]; then
    read -rsp "Vault passphrase (must match an existing vault, or set a new one): " PASS; echo
    umask 077
    printf 'HOWDY_BRIDGE_PASSPHRASE=%s\n' "$PASS" > "$CONF/passphrase.env"
    chmod 0600 "$CONF/passphrase.env"
else
    echo "    already exists, leaving it"
fi

# If this machine has a TPM, seal the vault key to it. The bridge auto-detects
# the sealed key at runtime; the disk passphrase then becomes a fallback only.
if [ -e /dev/tpmrm0 ] && [ ! -e "$CONF/vault.key.tpm" ]; then
    echo "==> TPM detected: sealing the vault key (migrates an existing vault)"
    # Needs the 'tss' group, which this session may not have yet, so use sg.
    # Source the passphrase file so the secret never hits the command line.
    if sg tss -c "set -a; . '$CONF/passphrase.env'; set +a; '$BIN' --tpm-init"; then
        echo "    vault key sealed to TPM."
    else
        echo "    WARN: tpm-init failed (TPM access? wrong passphrase?); the vault will"
        echo "          use disk-passphrase encryption instead. Re-run later with:"
        echo "          sg tss -c '$BIN --tpm-init'"
    fi
else
    [ -e "$CONF/vault.key.tpm" ] && echo "==> TPM key already present, skipping seal" \
        || echo "==> no TPM (/dev/tpmrm0); using disk-passphrase encryption"
fi

echo "==> installing unit -> $UNIT_DIR/howdy-passkey-bridge.service"
install -m 0644 "$HPB_ROOT/scripts/howdy-passkey-bridge.service" "$UNIT_DIR/howdy-passkey-bridge.service"
systemctl --user daemon-reload
systemctl --user enable howdy-passkey-bridge.service

echo
echo "==> Enabled. If you just ran setup-env.sh (joined the 'usbip' and 'tss' groups),"
echo "    LOG OUT and back in once so the session picks them up, then:"
echo "      systemctl --user start howdy-passkey-bridge.service"
echo "    Check it:  systemctl --user status howdy-passkey-bridge.service"
echo "               journalctl --user -u howdy-passkey-bridge -f"
