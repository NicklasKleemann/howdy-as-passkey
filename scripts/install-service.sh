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

echo "==> installing unit -> $UNIT_DIR/howdy-passkey-bridge.service"
install -m 0644 "$HPB_ROOT/scripts/howdy-passkey-bridge.service" "$UNIT_DIR/howdy-passkey-bridge.service"
systemctl --user daemon-reload
systemctl --user enable howdy-passkey-bridge.service

echo
echo "==> Enabled. If you just ran setup-env.sh (joined the 'usbip' group),"
echo "    LOG OUT and back in once so the session picks up the group, then:"
echo "      systemctl --user start howdy-passkey-bridge.service"
echo "    Check it:  systemctl --user status howdy-passkey-bridge.service"
echo "               journalctl --user -u howdy-passkey-bridge -f"
