#!/usr/bin/env bash
# Build Security Watchdog, install it on the TV, let it switch debugging off, and push its config.
#   TV_HOST=<tv ip> addons/security-watchdog/install.sh [config.json]
#   NO_AUTOCLOSE=1 ...   install without WRITE_SECURE_SETTINGS: it watches and reports, but cannot close ADB
# The config can hold an MQTT password: keep it outside the repo (backup/ is git-ignored). This script
# never prints it. Network ADB on port 5555 is plaintext, so push a config with a password over USB or
# Wireless debugging where the TV offers it, and give the TV its own MQTT user (integrations/home-assistant/).
set -euo pipefail
CONFIG="${1:-}"
: "${TV_HOST:?set TV_HOST to the TV IP address}"
if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || { echo "no such file: $CONFIG" >&2; exit 1; }
  CONFIG="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"
  # Git Bash on Windows: the venv's Python wants C:/... rather than /c/...
  if command -v cygpath >/dev/null 2>&1; then CONFIG="$(cygpath -m "$CONFIG")"; fi
fi
cd "$(dirname "$0")"
TOOLS="$(cd ../../tools && pwd)"
PY=$TOOLS/venv/bin/python
[ -x "$PY" ] || PY=$TOOLS/venv/Scripts/python.exe
export MSYS_NO_PATHCONV=1
PKG=io.github.securetv.watchdog
# Script paths stay relative: with MSYS_NO_PATHCONV, Git Bash would hand Windows Python a /c/... path.
tv() { "$PY" -I ../../tools/tv.py "$@"; }

if [ -n "$CONFIG" ]; then
  # Catch a typo here rather than on the TV. The app checks it again and keeps the old config if it is bad.
  "$PY" -I -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$CONFIG" \
    || { echo "ERROR: $CONFIG is not valid JSON" >&2; exit 1; }
fi

[ -f local.properties ] || { [ -n "${ANDROID_HOME:-}" ] && echo "sdk.dir=${ANDROID_HOME//\\//}" > local.properties; } || true
if [ -n "${JAVA_HOME:-}" ]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
./gradlew assembleRelease -q --console=plain
"$PY" -I ../../tools/b64push.py app/build/outputs/apk/release/app-release.apk /data/local/tmp/security-watchdog.apk
OUT=$(tv 'pm install -r /data/local/tmp/security-watchdog.apk; rm -f /data/local/tmp/security-watchdog.apk')
echo "$OUT"
case "$OUT" in *Success*) ;; *) echo "ERROR: pm install failed" >&2; exit 1 ;; esac

if [ "${NO_AUTOCLOSE:-0}" != 1 ]; then
  # Only this lets the watchdog switch debugging off; it watches and reports without it.
  tv "pm grant $PKG android.permission.WRITE_SECURE_SETTINGS && echo auto-close allowed"
fi
# Alerts in the notification shade on Android 13+ (older versions need no grant and print an error here).
tv "pm grant $PKG android.permission.POST_NOTIFICATIONS 2>/dev/null; true"
# TCL firmware stops apps that lack the auto-start app-op; other TVs do not know the op and ignore it.
tv "cmd appops set $PKG AUTO_START allow 2>/dev/null; cmd appops set $PKG APP_AUTO_START allow 2>/dev/null; appops write-settings 2>/dev/null; true"

if [ -n "$CONFIG" ]; then
  STAGE=/data/local/tmp/security-watchdog-config.json
  "$PY" -I ../../tools/b64push.py "$CONFIG" "$STAGE" >/dev/null
  # Android 8 and 9 have no `content write`: they print the usage or "Unsupported operation", so fall back to
  # the app's external folder, which the app empties as soon as it reads it.
  tv "o=\$(content write --uri content://$PKG.config/config.json < $STAGE 2>&1); case \"\$o\" in *'Unsupported operation'*|*'Error'*|*'usage'*) mkdir -p /sdcard/Android/data/$PKG/files && cp $STAGE /sdcard/Android/data/$PKG/files/config.json && echo 'config copied (Android 8/9)';; *) echo 'config pushed';; esac; rm -f $STAGE"
fi

tv "am start -n $PKG/.MainActivity >/dev/null; echo opened"
if [ -n "$CONFIG" ]; then
  sleep 4   # the app reads the config as it starts
  STATUS=$(tv "content query --uri content://$PKG.config/status" | tr -d '\r')
  echo "config: ${STATUS#*result=}"
  case "$STATUS" in *"result=ok"*) ;; *) echo "WARNING: the TV did not take the config; the old one (or none) stays in use" >&2 ;; esac
fi
echo "Installed. Security Watchdog is open on the TV; press Home and answer Show card for the card."
if [ "${NO_AUTOCLOSE:-0}" != 1 ]; then
  echo "Debugging switches itself off adb_autoclose_minutes (default 30) after it comes on, this session included."
  echo "On the TV, 'Keep it on longer' restarts the clock; adb_autoclose_minutes: 0 in config.json turns it off."
fi
