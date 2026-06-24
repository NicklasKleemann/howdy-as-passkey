#!/usr/bin/env bash
# End-to-end integration test for howdy-passkey-bridge.
#
# Drives a real makeCredential through the attached virtual authenticator with
# libfido2 and asserts the resulting passkey is user-verified (uv=1), then
# cryptographically verifies it.
#
# REQUIRES (not a CI test — it needs hardware and a live face):
#   - an IR camera with an enrolled Howdy face,
#   - the 'usbip' group active in this shell. Run it as:
#       sg usbip -c scripts/test-e2e.sh
#     (or just ./scripts/test-e2e.sh after logging out/in once post-setup)
#   - fido2-cred (libfido2), go, usbip, the vhci-hcd module loaded.
#
# A face scan will be requested during the run.
set -euo pipefail

HPB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HPB_ROOT"

command -v fido2-cred >/dev/null || { echo "FAIL: fido2-cred (libfido2) not installed"; exit 1; }

echo "==> building bridge"
# shellcheck disable=SC1091
. scripts/env.sh
( cd src/virtual-fido && go build -o "$HPB_ROOT/bin/howdy-bridge" ./cmd/howdy-bridge )

VAULT="$(mktemp -u /tmp/hb-e2e-vault.XXXXXX.json)"
LOG="$(mktemp /tmp/hb-e2e.XXXXXX.log)"
CRED="$(mktemp /tmp/hb-e2e-cred.XXXXXX)"
BRIDGE_PID=""

cleanup() {
    [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
    usbip detach -p 00 2>/dev/null || true
    rm -f "$VAULT" "$LOG" "$CRED"
}
trap cleanup EXIT

echo "==> starting bridge"
./bin/howdy-bridge --passphrase e2e-test --vault "$VAULT" >"$LOG" 2>&1 &
BRIDGE_PID=$!

echo "==> waiting for the virtual authenticator to attach"
DEV=""
for _ in $(seq 1 20); do
    DEV="$(fido2-token -L 2>/dev/null | grep -i 'Virtual FIDO' | head -1 | cut -d: -f1 || true)"
    [ -n "$DEV" ] && break
    sleep 0.5
done
[ -n "$DEV" ] || { echo "FAIL: device did not attach"; echo "--- bridge log ---"; cat "$LOG"; exit 1; }
echo "    device: $DEV"

echo "==> makeCredential with user-verification (Howdy will prompt) ..."
CDH="$(head -c32 /dev/urandom | base64)"
USERID="$(head -c16 /dev/urandom | base64)"
printf '%s\nexample.com\ntestuser\n%s\n' "$CDH" "$USERID" | fido2-cred -M -v "$DEV" > "$CRED"

echo "==> asserting UV bit in authenticator data"
python3 - "$CRED" <<'PY'
import base64, hashlib, sys
lines = open(sys.argv[1]).read().splitlines()
# fido2-cred -M output line 4 is the authenticator data (base64, CBOR-wrapped).
data = base64.b64decode(lines[3])
rp_hash = hashlib.sha256(b"example.com").digest()
i = data.find(rp_hash)
if i < 0:
    print("FAIL: rpIdHash not found in authData"); sys.exit(1)
flags = data[i + 32]
print("    authData flags = 0x%02x  (UP=%d UV=%d AT=%d)" % (
    flags, bool(flags & 0x01), bool(flags & 0x04), bool(flags & 0x40)))
if not (flags & 0x04):
    print("FAIL: UV bit not set — Howdy gate did not mark user-verified"); sys.exit(1)
PY

echo "==> verifying credential (uv required)"
fido2-cred -V -v -i "$CRED" >/dev/null

echo
echo "PASS: makeCredential produced a verified uv=1 passkey via Howdy, no sudo."
