#!/bin/sh
# Pull the live VoWiFi activation config off a debuggable Android build of the messaging app
# and write it as the plist `epdg-connect --activation` / EPDG_ACTIVATION_CONFIG expect.
#
# The app keeps the serialized VoWiFiConfig — `cred` (imsIndividualCredentials), `bundle`
# (carrier bundle), `instance`, `tunnel` {certificate_der, key_der, subscriber_id} — as the
# `vowifiConfig` string preference (an XML plist) in shared_prefs/setup_prefs.xml. The
# certificate is reissued by provisioning and lives a month, so pull a fresh one when the
# live test fails with AUTHENTICATION_FAILED at IKE_AUTH #1.
#
# Usage: scripts/pull-activation-config.sh [package] [output.plist]
set -eu
PKG="${1:-com.localob.messaging.giraffe}"
OUT="${2:-${TMPDIR:-/tmp}/epdg-activation-config.plist}"
PREFS="$(mktemp)"
trap 'rm -f "$PREFS"' EXIT
adb exec-out run-as "$PKG" cat shared_prefs/setup_prefs.xml > "$PREFS"
# (the program comes in on stdin, so the preferences file goes in by name)
python3 -I - "$OUT" "$PREFS" <<'PY'
import html, plistlib, re, subprocess, sys, tempfile, os
xml = open(sys.argv[2], encoding="utf-8", errors="replace").read()
m = re.search(r'<string name="vowifiConfig">(.*?)</string>', xml, re.S)
if not m:
    sys.exit("no vowifiConfig preference in setup_prefs.xml (is VoWiFi set up on this device?)")
cfg = plistlib.loads(html.unescape(m.group(1)).encode("utf-8"))
tunnel = cfg.get("tunnel")
if not tunnel:
    sys.exit("the config carries no tunnel credentials (no ePDG line on this device)")
with open(sys.argv[1], "wb") as f:
    plistlib.dump(cfg, f)
with tempfile.NamedTemporaryFile("wb", suffix=".der", delete=False) as f:
    f.write(tunnel["certificate_der"]); der = f.name
dates = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", der, "-noout", "-subject", "-enddate"], capture_output=True, text=True).stdout
os.unlink(der)
print(f"wrote {sys.argv[1]} for {cfg['cred'].get('username')}\n{dates.strip()}")
PY
echo "run the live test with: EPDG_ACTIVATION_CONFIG=$OUT cargo test --test live_tmobile -- --nocapture"
