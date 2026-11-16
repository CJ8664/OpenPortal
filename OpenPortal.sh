#!/usr/bin/env bash
#
# OpenPortal.sh - bash port of OpenPortal.ps1 (CoderPlusPlus/OpenPortal)
#
# SYNOPSIS
#   Provision the Meta Portal+ (aloha) to run the latest Google Services with
#   the privileges it needs, using the root exploit.
#
# DESCRIPTION
#   Faithful 1:1 port of OpenPortal.ps1 for macOS and Linux, with ONE
#   deliberate omission, at the owner's request (2026-11-15):
#
#     Phase 5 (genuine Messenger, com.facebook.orca) is NOT included.
#
#   Everything Messenger-only went with it: the Phase 5 helpers
#   (Get-ApkSignerCert, Get-SignatureHashCode, Get-MessengerApk,
#   Expand-MessengerXapk, Set-PresenceMessengerTrust, the hardcoded
#   Messenger cert), the apkeep download path, and the Java / apksig
#   bootstrap - in the .ps1 those tools are used only by Phase 5.
#
#   Other platform translations, kept as close to the original as bash
#   allows:
#     - adb.exe / java.exe / python.exe      -> adb / java / python3
#     - $env:LOCALAPPDATA\Temp\opencode\...  -> ~/Library/Caches/opencode/...
#                                               (macOS) or
#                                               ${XDG_CACHE_HOME:-~/.cache}/opencode/...
#                                               (Linux) for the default log root
#     - $env:TEMP                            -> ${TMPDIR:-/tmp}
#     - $env:USERPROFILE\Downloads           -> ~/Downloads
#     - Expand-Archive                       -> unzip (python3 zipfile fallback)
#     - Invoke-WebRequest                    -> curl
#     - platform-tools-latest-windows.zip    -> platform-tools-latest-darwin.zip
#                                               or platform-tools-latest-linux.zip
#     - Python bootstrap: the .ps1 downloads the Windows embeddable Python
#       and patches its ._pth file. There is no equivalent single-file
#       download for macOS/Linux, so this port requires a system python3
#       (preinstalled on macOS and on most Linux distros) and stops with
#       install guidance if none is found. The ._pth patch is a no-op
#       outside the Windows embeddable build and is omitted.
#     - Arguments are GNU-style (--phases) instead of PowerShell-style
#       (-Phases); the single-dash forms are also accepted.
#
#   Cumulative, idempotent, re-runnable: each run brings the Portal up to
#   the highest implemented AND verified phase, so it is the single "get
#   back to the last verified step" command.
#
#   Implemented phases
#     1  Root exploit provisioned + TCP 5555 wireless-adb recovery channel
#        (persist.adb.tcp.port=5555).
#     2  Install the latest Google Play Services supported on this hardware,
#        with the real GSF and Play Store it needs. No stub.
#     3  Use the exploit to grant the Google apps the signature|privileged
#        permissions they need (MANAGE_USERS etc.).
#     4  Disable Meta's FacebookAppVerifier so the Play Store can install
#        apps, and confirm the grant holds for com.google.android.gms and
#        com.android.vending.
#
#   Every phase is safe to run again: if the target state already holds,
#   the phase is skipped and reported as already-satisfied.
#
# USAGE
#   ./OpenPortal.sh [--phases 1,2,3,4] [--serial <serial>]
#                   [--tool-root <dir>] [--log-root <dir>]
#                   [--attempts <1-100>] [--rebuild]
#                   [--play-dir <dir>] [--gms-apk <file>] [--gsf-apk <file>]
#                   [--gsf-login-apk <file>] [--vending-bundle <file>]
#                   [--grant-packages <pkg[,pkg...]>]
#
# EXAMPLES
#   ./OpenPortal.sh
#   ./OpenPortal.sh --serial 818PGA02P1200D15
#   ./OpenPortal.sh --phases 1,2
#
# Original: https://github.com/CoderPlusPlus/OpenPortal (Unlicense)
# Provisioner: portal-root-kiosk-satellite-main, bundled next to this script.

# NOTE: no `set -e` / `set -u`, mirroring the original's flow where most
# helpers handle their own errors and the top level reports a single
# PORTAL_PROVISION_FAILED. Empty-array expansion also stays safe on the
# bash 3.2 that ships with older macOS.
set -o pipefail

# ---------------------------------------------------------------------------
# Defaults / parameters
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_DIR="$SCRIPT_DIR/deps"

PHASES="1,2,3,4"
SERIAL=""
TOOL_ROOT=""
ATTEMPTS=12
REBUILD=0

if [ "$(uname -s)" = "Darwin" ]; then
    DEFAULT_LOG_ROOT="$HOME/Library/Caches/opencode/portal-provision"
else
    DEFAULT_LOG_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/opencode/portal-provision"
fi
LOG_ROOT="$DEFAULT_LOG_ROOT"

PLAY_DIR=""
GMS_APK=""
GSF_APK=""
GSF_LOGIN_APK=""
VENDING_BUNDLE=""

GRANT_PACKAGES="com.google.android.gms"

PYTHON_EXE="python3"
PORTAL_IP=""

# ---------------------------------------------------------------------------
# Output helpers (Write-Host -ForegroundColor in the original)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_CYAN="$(printf '\033[36m')"; C_GREEN="$(printf '\033[32m')"
    C_YELLOW="$(printf '\033[33m')"; C_RED="$(printf '\033[31m')"
    C_WHITE="$(printf '\033[37m')"; C_GRAY="$(printf '\033[90m')"
    C_OFF="$(printf '\033[0m')"
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_WHITE=""; C_GRAY=""; C_OFF=""
fi

write_phase()  { printf '\n== %s\n' "$C_CYAN$1$C_OFF"; }
write_ok()     { printf '[ok]  %s\n' "$C_GREEN$1$C_OFF"; }
write_notice() { printf '[..]  %s\n' "$C_YELLOW$1$C_OFF"; }
write_bad()    { printf '[!!]  %s\n' "$C_RED$1$C_OFF"; }

die() {
    write_bad "$1"
    printf '%s\n' "${C_RED}PORTAL_PROVISION_FAILED${C_OFF}"
    exit 1
}

# A padded ASCII box for the final message.
write_done_box() {
    text="$1"; width="${2:-64}"
    if [ "${#text}" -gt $((width - 2)) ]; then width=$((${#text} + 2)); fi
    border="+"; i=0; while [ $i -lt $width ]; do border="${border}-"; i=$((i+1)); done; border="${border}+"
    blank="|";  i=0; while [ $i -lt $width ]; do blank="${blank} ";  i=$((i+1)); done; blank="${blank}|"
    pad=$((width - ${#text})); left=$((pad / 2)); right=$((pad - left))
    mid="|"; i=0; while [ $i -lt $left ];  do mid="${mid} "; i=$((i+1)); done
    mid="${mid}${text}"
    i=0; while [ $i -lt $right ]; do mid="${mid} "; i=$((i+1)); done; mid="${mid}|"
    printf '\n%s\n%s\n%s\n%s\n%s\n\n' \
        "$C_GREEN$border$C_OFF" "$C_GREEN$blank$C_OFF" "$C_GREEN$mid$C_OFF" \
        "$C_GREEN$blank$C_OFF" "$C_GREEN$border$C_OFF"
}

# Prompt for a single Y/N keypress. Returns 0 for Y, 1 for N; any other key
# prints $2 and asks again. Reads one keystroke (no Enter) on a terminal,
# or a line when input is redirected (so a scripted/piped run can't hang).
read_yes_no() {
    prompt="$1"; invalid="$2"
    while :; do
        printf '%s\n' "$C_CYAN$prompt$C_OFF"
        if [ -t 0 ]; then
            key=""
            IFS= read -r -n 1 key || key=""
            printf '%s\n' "$key"
        else
            answer=""; IFS= read -r answer || answer=""
            key="$(printf '%s' "$answer" | tr '[:lower:]' '[:upper:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            key="$(printf '%.1s' "$key")"
        fi
        key_upper="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')"
        if [ "$key_upper" = "Y" ]; then return 0; fi
        if [ "$key_upper" = "N" ]; then return 1; fi
        printf '%s\n\n' "$C_RED$invalid$C_OFF"
    done
}

# Show the risk warning and require an explicit Y. Returns 0 to continue.
confirm_risk_warning() {
    printf '\n'
    printf '%s\n\n' "${C_YELLOW}USE AT YOUR OWN RISK.  I AM NOT RESPONSIBLE IF THE SCRIPT RESULTS IN A BRICKED DEVICE!${C_OFF}"
    printf '%s\n' "I've tested the script myself, but like any script that uses exploits, there's always a"
    printf '%s\n' "small risk of a boot loop or other unrecoverable error happening.  You agree by using the"
    printf '%s\n\n' "script that you have read and understand this warning."
    read_yes_no \
        "Press [Y] to acknowledge and continue or [N] to exit." \
        "Invalid key, please choose [Y] to acknowledge the warning and continue or [N] to exit."
}

# ---------------------------------------------------------------------------
# Dependency bootstrap. For each tool we first look for one that is already
# present (on PATH or in an installed Android SDK); we only download into
# <script>/deps/ when nothing usable exists.
# (Java and apksig, bootstrapped here in the .ps1, are used only by the
# omitted Phase 5, so they are not bootstrapped in this port.)
# ---------------------------------------------------------------------------
download_file() {
    url="$1"; outfile="$2"
    mkdir -p "$(dirname "$outfile")" || return 1
    write_notice "downloading $(basename "$outfile") ..."
    tmp="${outfile}.download"
    rm -f "$tmp"
    if curl -fsSL -o "$tmp" "$url"; then
        mv -f "$tmp" "$outfile"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# Expand a zip archive into a directory (unzip, python3 zipfile fallback).
expand_archive() {
    zip="$1"; dest="$2"
    mkdir -p "$dest" || return 1
    if command -v unzip >/dev/null 2>&1; then
        unzip -o -q "$zip" -d "$dest"
    else
        python3 -m zipfile -e "$zip" "$dest"
    fi
}

# --- find-what-already-exists helpers (print a path, or nothing) ---

get_adb_path() {
    cmd="$(command -v adb 2>/dev/null)"
    if [ -n "$cmd" ]; then printf '%s\n' "$cmd"; return 0; fi
    local_adb="$DEPS_DIR/platform-tools/adb"
    if [ -f "$local_adb" ]; then printf '%s\n' "$local_adb"; return 0; fi
    for root in "$ANDROID_HOME" "$ANDROID_SDK_ROOT" \
                "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        if [ -n "$root" ]; then
            p="$root/platform-tools/adb"
            if [ -f "$p" ]; then printf '%s\n' "$p"; return 0; fi
        fi
    done
    return 0
}

get_python_path() {
    for name in python3 python; do
        cmd="$(command -v "$name" 2>/dev/null)"
        if [ -n "$cmd" ] && [ -s "$cmd" ]; then printf '%s\n' "$cmd"; return 0; fi
    done
    local_py="$DEPS_DIR/python/bin/python3"
    if [ -f "$local_py" ]; then printf '%s\n' "$local_py"; return 0; fi
    return 0
}

# --- ensure-available: use what exists, download only what is missing ---

ensure_adb() {
    adb_path="$(get_adb_path)"
    if [ -n "$adb_path" ]; then
        printf 'adb:    %s\n' "$adb_path"
        PATH="$(dirname "$adb_path"):$PATH"; export PATH
        return 0
    fi
    write_notice "adb not found; fetching Android platform-tools ..."
    case "$(uname -s)" in
        Darwin) zip_name="platform-tools-latest-darwin.zip" ;;
        Linux)  zip_name="platform-tools-latest-linux.zip" ;;
        *) die "Could not obtain adb (unsupported OS: $(uname -s))." ;;
    esac
    zip="$DEPS_DIR/platform-tools.zip"
    download_file "https://dl.google.com/android/repository/$zip_name" "$zip" \
        || die "Could not obtain adb (platform-tools download failed)."
    expand_archive "$zip" "$DEPS_DIR" || die "Could not obtain adb (platform-tools unzip failed)."
    rm -f "$zip"
    dir="$DEPS_DIR/platform-tools"
    if [ ! -f "$dir/adb" ]; then die "Could not obtain adb (platform-tools download failed)."; fi
    chmod +x "$dir/adb" 2>/dev/null
    printf 'adb:    %s  (downloaded)\n' "$dir/adb"
    PATH="$dir:$PATH"; export PATH
}

ensure_python() {
    py="$(get_python_path)"
    if [ -z "$py" ]; then
        die "Python 3 not found. Install Python 3 and re-run (macOS: https://www.python.org/downloads/ or 'brew install python'; Linux: your distribution's python3 package). The .ps1's Windows embeddable-Python download has no macOS/Linux equivalent in this port."
    fi
    printf 'Python: %s\n' "$py"
    PYTHON_EXE="$py"
}

bootstrap_deps() {
    write_phase "Checking tools (adb, Python)"
    ensure_adb
    ensure_python
    write_ok "tools ready"
}

# ---------------------------------------------------------------------------
# adb wrappers. invoke_adb prints output and dies on a non-zero exit (the
# .ps1's Invoke-Adb throws); invoke_adb_quiet fills ADB_Q_OUT / ADB_Q_CODE
# and never dies (the .ps1's Invoke-AdbQuiet).
# ---------------------------------------------------------------------------
ADB_Q_OUT=""; ADB_Q_CODE=0

adb_raw() {
    # adb with no serial selection (device listing, connect, ...).
    adb "$@"
}

invoke_adb() {
    if [ -n "$SERIAL" ]; then
        out="$(adb -s "$SERIAL" "$@" 2>&1)"; code=$?
    else
        out="$(adb "$@" 2>&1)"; code=$?
    fi
    if [ $code -ne 0 ]; then
        die "adb $* failed ($code): $out"
    fi
    printf '%s\n' "$out" | sed -e 's/[[:space:]]*$//'
}

invoke_adb_quiet() {
    if [ -n "$SERIAL" ]; then
        ADB_Q_OUT="$(adb -s "$SERIAL" "$@" 2>&1)"; ADB_Q_CODE=$?
    else
        ADB_Q_OUT="$(adb "$@" 2>&1)"; ADB_Q_CODE=$?
    fi
    # Trim trailing whitespace/newlines, like the .ps1's .Trim().
    ADB_Q_OUT="$(printf '%s' "$ADB_Q_OUT" | sed -e 's/[[:space:]]*$//')"
}

# Pick the USB serial if --serial was not given.
resolve_serial() {
    if [ -n "$SERIAL" ]; then
        saved_serial="$SERIAL"; SERIAL=""
        # get-state for the named serial, without the wrapper's -s defaulting
        state="$(adb -s "$saved_serial" get-state 2>&1 | sed -e 's/[[:space:]]*$//')"
        SERIAL="$saved_serial"
        if [ "$state" != "device" ]; then
            die "Serial '$SERIAL' is not ready (state: '$state'). Enable USB debugging and replug."
        fi
        return 0
    fi
    devices_out="$(adb devices 2>&1)"
    first=""; first_usb=""
    printf '%s\n' "$devices_out" | while IFS= read -r line; do :; done
    # Parse in the current shell (no pipeline subshell) for bash 3.2 compat.
    old_ifs="$IFS"; IFS='
'
    for line in $devices_out; do
        # Line form: <serial><whitespace>device...
        serial_part="$(printf '%s' "$line" | awk '$2=="device"{print $1}')"
        if [ -n "$serial_part" ]; then
            if [ -z "$first" ]; then first="$serial_part"; fi
            case "$serial_part" in
                *":"*) : ;;
                *) if [ -z "$first_usb" ]; then first_usb="$serial_part"; fi ;;
            esac
        fi
    done
    IFS="$old_ifs"
    if [ -n "$first_usb" ]; then SERIAL="$first_usb"
    elif [ -n "$first" ]; then SERIAL="$first"
    else
        die "No adb device. Enable Developer options + USB debugging, replug, and accept the prompt on the Portal."
    fi
}

get_portal_ip() {
    # Result in PORTAL_IP (cached). Empty when wlan0 has no IPv4 address yet.
    if [ -n "$PORTAL_IP" ]; then return 0; fi
    invoke_adb_quiet shell ip -4 addr show wlan0
    ip="$(printf '%s' "$ADB_Q_OUT" | grep -oE 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | awk '{print $2}')"
    if [ -n "$ip" ]; then PORTAL_IP="$ip"; fi
    return 0
}

# True when persist.adb.tcp.port=5555 AND a shell works over adb connect.
test_recovery_channel() {
    invoke_adb_quiet shell getprop persist.adb.tcp.port
    if [ "$ADB_Q_OUT" != "5555" ]; then return 1; fi
    get_portal_ip
    if [ -z "$PORTAL_IP" ]; then return 1; fi
    adb connect "${PORTAL_IP}:5555" >/dev/null 2>&1
    id_out="$(adb -s "${PORTAL_IP}:5555" shell id 2>&1)"
    case "$id_out" in *"uid=2000"*) return 0 ;; *) return 1 ;; esac
}

# Like test_recovery_channel but tolerant of the channel still coming up:
# after a reboot wlan0/adbd-5555 can take a little while, so retry.
wait_recovery_channel() {
    timeout_seconds="${1:-120}"
    deadline=$(( $(date +%s) + timeout_seconds ))
    while :; do
        if test_recovery_channel; then return 0; fi
        if [ "$(date +%s)" -ge $deadline ]; then return 1; fi
        PORTAL_IP=""   # re-read the IP each time (it may appear late)
        sleep 5
    done
}

# True if the file begins with the ZIP/APK magic "PK".
test_is_zip() {
    magic="$(head -c 2 "$1" 2>/dev/null)"
    [ "$magic" = "PK" ]
}

# Newest file matching a wildcard in a directory (by mtime), or nothing.
# A .apk filter also matches an APK saved without an extension (browsers
# drop it); other filters require their exact extension. Only real zip/APK
# files count. Implemented in python3 for identical mtime/version handling
# on macOS and Linux (their `stat` flags differ).
get_newest_file() {
    dir="$1"; filter="$2"
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then return 0; fi
    python3 - "$dir" "$filter" <<'PY'
import fnmatch, os, sys
directory, filt = sys.argv[1], sys.argv[2]
is_apk = filt.endswith(".apk")
base = filt
for ext in (".apk", ".apkm", ".xapk"):
    if base.endswith(ext):
        base = base[: -len(ext)]
        break
def is_zip(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"PK"
    except OSError:
        return False
best, best_mtime = None, None
try:
    names = os.listdir(directory)
except OSError:
    sys.exit(0)
for name in names:
    path = os.path.join(directory, name)
    if not os.path.isfile(path):
        continue
    match = fnmatch.fnmatch(name, filt)
    if not match and is_apk:
        match = fnmatch.fnmatch(name, base) and not name.endswith((".apk", ".apkm", ".xapk"))
    if not match or not is_zip(path):
        continue
    mtime = os.path.getmtime(path)
    if best_mtime is None or mtime > best_mtime:
        best, best_mtime = path, mtime
if best:
    print(best)
PY
}

# Highest-version com.google.android.gms_<x.y.z>* in a directory (not mtime).
get_newest_gms() {
    dir="$1"
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then return 0; fi
    python3 - "$dir" <<'PY'
import os, re, sys
directory = sys.argv[1]
def is_zip(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"PK"
    except OSError:
        return False
best, best_ver = None, None
try:
    names = os.listdir(directory)
except OSError:
    sys.exit(0)
for name in names:
    if name.endswith((".xapk", ".apkm")):
        continue
    m = re.search(r"com\.google\.android\.gms_(\d+)\.(\d+)\.(\d+)", name)
    if not m:
        continue
    path = os.path.join(directory, name)
    if not os.path.isfile(path) or not is_zip(path):
        continue
    ver = tuple(int(x) for x in m.groups())
    if best_ver is None or ver > best_ver:
        best, best_ver = path, ver
if best:
    print(best)
PY
}

test_package_installed() {
    pkg="$1"
    invoke_adb_quiet shell pm list packages "$pkg"
    # Match the whole line: "pm list packages <x>" filters by substring, so
    # com.google.android.gsf would otherwise also match ...gsf.login.
    old_ifs="$IFS"; IFS='
'
    found=1
    for line in $ADB_Q_OUT; do
        trimmed="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ "$trimmed" = "package:$pkg" ]; then found=0; break; fi
    done
    IFS="$old_ifs"
    return $found
}

# Install a single APK (upgrade in place), then confirm the package exists.
install_apk() {
    path="$1"; pkg="$2"
    if [ ! -f "$path" ]; then die "Missing APK for ${pkg}: $path"; fi
    printf 'install %s  <- %s\n' "$pkg" "$(basename "$path")"
    invoke_adb install -r "$path"
    if ! test_package_installed "$pkg"; then
        die "Install reported success but $pkg is not present"
    fi
}

# Meta's FacebookAppVerifier rejects every app not signed by Facebook.
# Disable it (the verifier itself AND adb-install verification, which also
# defaults to on after a factory reset) so installs go through.
disable_app_verifier() {
    invoke_adb_quiet shell settings get global package_verifier_enable
    cur="$ADB_Q_OUT"
    if [ "$cur" != "0" ]; then
        printf 'disabling package verifier (was %s)\n' "$cur"
        invoke_adb shell settings put global package_verifier_enable 0 >/dev/null
    fi
    invoke_adb_quiet shell settings get global verifier_verify_adb_installs
    adbcur="$ADB_Q_OUT"
    if [ "$adbcur" != "0" ]; then
        printf 'disabling adb-install verification (was %s)\n' "$adbcur"
        invoke_adb shell settings put global verifier_verify_adb_installs 0 >/dev/null
    fi
}

# dumpsys package <pkg> output, in DUMPSYS_OUT (local grep replaces the
# device-side grep the .ps1 used, with the same result).
dumpsys_package() {
    invoke_adb_quiet shell dumpsys package "$1"
    DUMPSYS_OUT="$ADB_Q_OUT"
}

past_signatures_line() {
    dumpsys_package android
    printf '%s' "$DUMPSYS_OUT" | grep -i 'past signatures' || true
}

# ---------------------------------------------------------------------------
# Phase 1 - root exploit + TCP 5555 recovery channel
# ---------------------------------------------------------------------------
run_provisioner() {
    # Remaining arguments are passed through to provision_portal.py.
    # Returns the provisioner's exit code in PROV_CODE.
    prov_path="$1"; shift
    "$PYTHON_EXE" "$prov_path" "$@"
    PROV_CODE=$?
}

invoke_phase1() {
    write_phase "Phase 1 - root exploit + TCP 5555 recovery channel"

    provisioner="$TOOL_ROOT/tools/provision_portal.py"
    if [ ! -f "$provisioner" ]; then die "Provisioner not found: $provisioner"; fi

    resolve_serial
    printf 'Device serial: %s\n' "$SERIAL"
    printf 'Model:         %s\n' "$(invoke_adb shell getprop ro.product.model)"
    printf 'Fingerprint:   %s\n' "$(invoke_adb shell getprop ro.build.fingerprint)"

    if wait_recovery_channel 15; then
        write_ok "Already at step 1 (persist.adb.tcp.port=5555 and a TCP shell works). Skipping."
        return 0
    fi

    # The provisioner builds these itself unless it is passed --skip-build,
    # so only require them up front for a --skip-build run.
    if [ $REBUILD -eq 0 ]; then
        so="$TOOL_ROOT/exploit/build/preload-portal-aloha-1041515800015050.so"
        sentinel="$TOOL_ROOT/exploit-sentinel/build/portal-exploit-sentinel.apk"
        for f in "$so" "$sentinel"; do
            if [ ! -f "$f" ]; then
                die "Missing build output: $f (run with --rebuild so the provisioner builds it, or build it first)"
            fi
        done
    fi

    log_dir="$LOG_ROOT/$(date '+%Y%m%d-%H%M%S')"
    mkdir -p "$log_dir" || die "Could not create log directory: $log_dir"
    printf 'Logs:          %s\n' "$log_dir"
    write_notice "This runs the kernel exploit and reboots the Portal a few times. Keep USB connected."

    if [ $REBUILD -eq 0 ]; then skip_build_arg="--skip-build"; else skip_build_arg=""; fi
    run_provisioner "$provisioner" --serial "$SERIAL" --persistent-wireless-adb \
        --attempts "$ATTEMPTS" --log-dir "$log_dir" $skip_build_arg
    if [ $PROV_CODE -ne 0 ]; then
        die "Provisioner exited with code $PROV_CODE (see $log_dir)"
    fi

    # Re-read state after the provisioner's reboots. Give the channel time
    # to come back (wlan0 IP + adbd's TCP listener) rather than failing fast.
    PORTAL_IP=""
    resolve_serial
    if ! wait_recovery_channel 180; then
        die "Phase 1 did not verify: persist.adb.tcp.port=5555 / TCP shell not working. Make sure the Portal is connected to Wi-Fi (the TCP channel needs a wlan0 IP)."
    fi
    write_ok "Phase 1 verified: TCP 5555 recovery channel is live."
}

# ---------------------------------------------------------------------------
# Phase 2 - install the real Google stack (no stub)
# ---------------------------------------------------------------------------
invoke_phase2() {
    write_phase "Phase 2 - install the real Google stack (no stub)"
    resolve_serial

    # The Google stack is not signed by Facebook, so Meta's verifier would
    # reject these adb installs on a fresh device. Disable it first.
    disable_app_verifier

    # Where the stack APKs live: --play-dir, then a bundled "stack" folder
    # next to this script, then ~/Downloads/play. Prefer a folder that
    # actually holds the stack, so an empty "stack" folder can't shadow
    # ~/Downloads/play.
    stack_dir=""
    first_existing=""
    for cand in "$PLAY_DIR" "$SCRIPT_DIR/stack" "$HOME/Downloads/play"; do
        if [ -z "$cand" ]; then continue; fi
        if [ -d "$cand" ] && [ -z "$first_existing" ]; then first_existing="$cand"; fi
        if [ -n "$(get_newest_gms "$cand")" ]; then stack_dir="$cand"; break; fi
    done
    if [ -z "$stack_dir" ]; then stack_dir="$first_existing"; fi
    if [ -n "$stack_dir" ]; then printf 'stack:  %s\n' "$stack_dir"; fi

    if [ -n "$GMS_APK" ]; then gms="$GMS_APK"; else gms="$(get_newest_gms "$stack_dir")"; fi
    if [ -n "$GSF_APK" ]; then gsf="$GSF_APK"; else gsf="$(get_newest_file "$stack_dir" 'com.google.android.gsf_*.apk')"; fi
    if [ -n "$GSF_LOGIN_APK" ]; then gsf_login="$GSF_LOGIN_APK"; else gsf_login="$(get_newest_file "$stack_dir" 'com.google.android.gsf.login_*.apk')"; fi
    if [ -n "$VENDING_BUNDLE" ]; then vending="$VENDING_BUNDLE"; else vending="$(get_newest_file "$stack_dir" 'com.android.vending_*.apkm')"; fi

    for pair in "GMS|$gms" "GSF|$gsf" "GSF login|$gsf_login" "Play Store|$vending"; do
        name="${pair%%|*}"; p="${pair#*|}"
        if [ -z "$p" ] || [ ! -f "$p" ]; then
            if [ -n "$stack_dir" ]; then where="in $stack_dir"; else where="in the stack folder"; fi
            die "Missing $name APK. Put the Google stack files $where (or pass --gms-apk/--gsf-apk/--gsf-login-apk/--vending-bundle)."
        fi
        printf '%-11s %s\n' "$name" "$(basename "$p")"
    done

    # The stub's com.google.android.gsf.gservices authority collides with
    # the real GSF.
    if test_package_installed "com.portal.gsfstub"; then
        write_notice "Removing GSF stub (com.portal.gsfstub)"
        invoke_adb uninstall com.portal.gsfstub
    fi

    # Order matters: GSF, then GSF login, then GMS, then the Play Store.
    # Skip anything already present (keeps re-runs fast).
    if test_package_installed "com.google.android.gsf"; then
        printf '%s\n' "com.google.android.gsf already installed; skipping"
    else
        install_apk "$gsf" "com.google.android.gsf"
    fi
    if test_package_installed "com.google.android.gsf.login"; then
        printf '%s\n' "com.google.android.gsf.login already installed; skipping"
    else
        install_apk "$gsf_login" "com.google.android.gsf.login"
    fi

    # GMS: skip only when the wanted version is already installed.
    want_gms="$(printf '%s' "$gms" | grep -oE 'com\.google\.android\.gms_[0-9]+\.[0-9]+\.[0-9]+' | sed 's/.*gms_//')"
    have_gms=""
    if test_package_installed "com.google.android.gms"; then
        dumpsys_package com.google.android.gms
        have_gms="$(printf '%s' "$DUMPSYS_OUT" | grep -oE 'versionName=[^[:space:]]+' | head -n 1 | sed 's/versionName=//')"
    fi
    if [ -n "$have_gms" ] && [ -n "$want_gms" ]; then
        case "$have_gms" in "$want_gms"*) gms_skip=1 ;; *) gms_skip=0 ;; esac
    else
        gms_skip=0
    fi
    if [ $gms_skip -eq 1 ]; then
        printf 'com.google.android.gms %s already installed; skipping\n' "$have_gms"
    else
        install_apk "$gms" "com.google.android.gms"
    fi

    if test_package_installed "com.android.vending"; then
        printf '%s\n' "com.android.vending already installed; leaving it"
    else
        tmp_base="${TMPDIR:-/tmp}"
        splits="$tmp_base/vending_splits"
        rm -rf "$splits"; mkdir -p "$splits" || die "Could not create $splits"
        zip="$tmp_base/vending.zip"
        cp -f "$vending" "$zip" || die "Could not copy the Play Store bundle."
        expand_archive "$zip" "$splits" || die "Could not unpack the Play Store bundle."
        parts_count=1
        extra_parts=""
        for split_name in split_config.arm64_v8a.apk split_config.en.apk; do
            fp="$splits/$split_name"
            if [ -f "$fp" ]; then extra_parts="$extra_parts $fp"; parts_count=$((parts_count+1)); fi
        done
        printf 'install-multiple com.android.vending  <- %s apk(s)\n' "$parts_count"
        # shellcheck disable=SC2086
        invoke_adb install-multiple "$splits/base.apk" $extra_parts
    fi

    for pkg in com.google.android.gsf com.google.android.gsf.login com.google.android.gms com.android.vending; do
        if ! test_package_installed "$pkg"; then
            die "Phase 2 did not verify: $pkg not installed"
        fi
    done
    dumpsys_package com.google.android.gms
    ver="$(printf '%s' "$DUMPSYS_OUT" | grep -oE 'versionName=[^[:space:]]+' | head -n 1 | sed 's/versionName=//')"
    if [ -n "$ver" ]; then printf 'GMS versionName=%s\n' "$ver"; fi
    write_ok "Phase 2 verified: real Google stack installed (no stub)."
}

# ---------------------------------------------------------------------------
# Phase 3 - grant the Google apps the signature|privileged permissions
# ---------------------------------------------------------------------------
invoke_phase3() {
    write_phase "Phase 3 - grant the Google apps their signature|privileged permissions"
    resolve_serial

    fwsigs="$(past_signatures_line)"
    if printf '%s' "$fwsigs" | grep -iE 'past signatures:\[.*flags: 4' >/dev/null 2>&1; then
        write_ok "Framework already has a PERMISSION-capable past signature; skipping Phase 3."
        return 0
    fi

    provisioner="$TOOL_ROOT/tools/provision_portal.py"
    if [ ! -f "$provisioner" ]; then die "Provisioner not found: $provisioner"; fi

    if test_recovery_channel; then
        write_ok "Recovery channel verified (persist.adb.tcp.port=5555, TCP shell works)."
    else
        write_notice "TCP 5555 recovery channel is NOT working; a boot loop would need a factory reset."
    fi

    log_dir="$LOG_ROOT/$(date '+%Y%m%d-%H%M%S')"
    mkdir -p "$log_dir" || die "Could not create log directory: $log_dir"
    printf 'Logs:          %s\n' "$log_dir"
    printf 'Grant cert of: %s\n' "$GRANT_PACKAGES"
    write_notice "This injects Google's cert as a PERMISSION-capable past signature of the framework, then reboots."

    if [ $REBUILD -eq 0 ]; then skip_build_arg="--skip-build"; else skip_build_arg=""; fi
    run_provisioner "$provisioner" --serial "$SERIAL" --permission-grants \
        --permission-grant-packages "$GRANT_PACKAGES" \
        --attempts "$ATTEMPTS" --log-dir "$log_dir" $skip_build_arg
    if [ $PROV_CODE -ne 0 ]; then
        die "Provisioner exited with code $PROV_CODE (see $log_dir). If the Portal is boot-looping, recover with: adb connect <ip>:5555 ; \"$PYTHON_EXE\" \"$provisioner\" --serial <ip>:5555 --permission-grants-restore --skip-build"
    fi

    PORTAL_IP=""
    resolve_serial
    invoke_adb_quiet shell getprop sys.boot_completed
    if [ "$ADB_Q_OUT" != "1" ]; then
        die "Phase 3 did not verify: sys.boot_completed=$ADB_Q_OUT"
    fi
    past_signatures_line
    write_ok "Phase 3 ran and the device booted. (Launching the Play Store and signing in are manual, after Phase 4.)"
}

# ---------------------------------------------------------------------------
# Phase 4 - let the Play Store install apps + verify Google Services
# ---------------------------------------------------------------------------
invoke_phase4() {
    write_phase "Phase 4 - allow Play Store installs + verify Google Services"
    resolve_serial

    # Meta's FacebookAppVerifier rejects every app not signed by Facebook,
    # so the Play Store (and Aurora) cannot install anything until Android
    # is told to skip that check. (Phase 2 already did this.)
    disable_app_verifier
    invoke_adb_quiet shell settings get global package_verifier_enable
    if [ "$ADB_Q_OUT" != "0" ]; then
        die "could not disable the package verifier"
    fi

    # Confirm the grant from Phase 3 still holds for the Google apps.
    for pkg in com.google.android.gms com.android.vending; do
        dumpsys_package "$pkg"
        if ! printf '%s' "$DUMPSYS_OUT" | grep -q 'MANAGE_USERS: granted=true'; then
            die "$pkg does not have MANAGE_USERS granted (run Phase 3 first)"
        fi
        write_ok "$pkg MANAGE_USERS granted"
    done

    write_ok "Phase 4 done: the Play Store can install apps and Google Services is privileged."
    printf '%s\n' "Manual: in the Play Store, install Google Home / Photos / YouTube, then sign in through Photos."
}

# ---------------------------------------------------------------------------
# Argument parsing + run
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: ./OpenPortal.sh [options]

  --phases <list>         Comma-separated phases to run (default: 1,2,3,4).
                          Phase 5 (Messenger) is not included in this port.
  --serial <serial>       adb serial of the Portal (USB). Auto-detected if omitted.
  --tool-root <dir>       Path to the portal-root-kiosk-satellite-main checkout.
                          Default: portal-root-kiosk-satellite-main next to this script.
  --log-root <dir>        Directory for per-run provisioner logs.
  --attempts <1-100>      Max exploit attempts passed to the provisioner. Default: 12.
  --rebuild               Build the exploit before provisioning. Off by default.
  --play-dir <dir>        Folder holding the Google stack files.
  --gms-apk <file>        Google Play Services APK.
  --gsf-apk <file>        Google Services Framework APK.
  --gsf-login-apk <file>  Google Account Manager / GSF login APK.
  --vending-bundle <file> Play Store .apkm bundle.
  --grant-packages <list> Phase 3 grant packages. Default: com.google.android.gms.
  --help                  Show this help and exit.
EOF
}

while [ $# -gt 0 ]; do
    # Accept both --name and the PowerShell-style -Name (case-insensitive key).
    raw_key="$1"
    key="$(printf '%s' "$raw_key" | sed 's/^-*//' | tr '[:upper:]' '[:lower:]')"
    case "$key" in
        help|h) usage; exit 0 ;;
        rebuild) REBUILD=1; shift ;;
        phases|serial|tool-root|log-root|attempts|play-dir|gms-apk|gsf-apk|gsf-login-apk|vending-bundle|grant-packages)
            if [ $# -lt 2 ]; then write_bad "$raw_key needs a value."; exit 1; fi
            value="$2"
            # Also support --name=value, handled below before this loop runs
            # for the first argument only in practice; the two-arg form is
            # the documented one.
            case "$key" in
                phases) PHASES="$value" ;;
                serial) SERIAL="$value" ;;
                tool-root) TOOL_ROOT="$value" ;;
                log-root) LOG_ROOT="$value" ;;
                attempts) ATTEMPTS="$value" ;;
                play-dir) PLAY_DIR="$value" ;;
                gms-apk) GMS_APK="$value" ;;
                gsf-apk) GSF_APK="$value" ;;
                gsf-login-apk) GSF_LOGIN_APK="$value" ;;
                vending-bundle) VENDING_BUNDLE="$value" ;;
                grant-packages) GRANT_PACKAGES="$value" ;;
            esac
            shift 2 ;;
        *=*)
            # --name=value form
            name_part="$(printf '%s' "$raw_key" | sed 's/^-*//' | cut -d= -f1 | tr '[:upper:]' '[:lower:]')"
            value_part="$(printf '%s' "$raw_key" | cut -d= -f2-)"
            case "$name_part" in
                phases) PHASES="$value_part" ;;
                serial) SERIAL="$value_part" ;;
                tool-root) TOOL_ROOT="$value_part" ;;
                log-root) LOG_ROOT="$value_part" ;;
                attempts) ATTEMPTS="$value_part" ;;
                play-dir) PLAY_DIR="$value_part" ;;
                gms-apk) GMS_APK="$value_part" ;;
                gsf-apk) GSF_APK="$value_part" ;;
                gsf-login-apk) GSF_LOGIN_APK="$value_part" ;;
                vending-bundle) VENDING_BUNDLE="$value_part" ;;
                grant-packages) GRANT_PACKAGES="$value_part" ;;
                rebuild) REBUILD=1 ;;
                *) write_bad "Unknown option: $raw_key"; usage; exit 1 ;;
            esac
            shift ;;
        *) write_bad "Unknown option: $raw_key"; usage; exit 1 ;;
    esac
done

case "$ATTEMPTS" in
    ''|*[!0-9]*) write_bad "--attempts: '$ATTEMPTS' is not a number (1-100)."; exit 1 ;;
esac
if [ "$ATTEMPTS" -lt 1 ] || [ "$ATTEMPTS" -gt 100 ]; then
    write_bad "--attempts: '$ATTEMPTS' is out of range (1-100)."
    exit 1
fi

if [ -z "$TOOL_ROOT" ]; then TOOL_ROOT="$SCRIPT_DIR/portal-root-kiosk-satellite-main"; fi

# Phase catalogue, in order. Only phases 1-4 exist in this port.
KNOWN_PHASES="1 2 3 4"

wanted_list=""
old_ifs="$IFS"; IFS=','
for tok in $PHASES; do
    IFS="$old_ifs"
    t="$(printf '%s' "$tok" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ -z "$t" ]; then IFS=','; continue; fi
    case "$t" in
        *[!0-9]*)
            write_bad "--phases: '$t' is not a phase number. Known phases: 1, 2, 3, 4"
            exit 1 ;;
        5)
            write_bad "--phases: Phase 5 (Messenger) is not included in this port, at your request to skip Messenger."
            exit 1 ;;
        1|2|3|4) wanted_list="$wanted_list $t" ;;
        *)
            write_bad "--phases: unknown phase(s): $t. Known phases: 1, 2, 3, 4"
            exit 1 ;;
    esac
    IFS=','
done
IFS="$old_ifs"

is_wanted() {
    case " $wanted_list " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

selected_text=""
for n in $KNOWN_PHASES; do
    if is_wanted "$n"; then
        if [ -z "$selected_text" ]; then selected_text="$n"; else selected_text="$selected_text,$n"; fi
    fi
done

if ! confirm_risk_warning; then
    printf '\n%s\n' "${C_YELLOW}Exiting at your request. Nothing was changed.${C_OFF}"
    exit 0
fi

printf '%s\n' "${C_WHITE}Meta Portal+ provisioning - phases: $selected_text${C_OFF}"

ran_list=""
bootstrap_deps
for n in $KNOWN_PHASES; do
    case "$n" in
        1) label="Phase 1 - root exploit + TCP 5555 recovery channel"; fn="invoke_phase1" ;;
        2) label="Phase 2 - install the real Google stack (no stub)"; fn="invoke_phase2" ;;
        3) label="Phase 3 - grant the Google apps their signature|privileged permissions"; fn="invoke_phase3" ;;
        4) label="Phase 4 - allow Play Store installs + verify Google Services"; fn="invoke_phase4" ;;
    esac
    if is_wanted "$n"; then
        $fn
        ran_list="$ran_list $n"
    else
        write_phase "$label"
        printf '%s\n' "${C_GRAY}[Skipped]${C_OFF}"
    fi
done

ran_text=""
for n in $ran_list; do
    if [ -z "$ran_text" ]; then ran_text="$n"; else ran_text="$ran_text,$n"; fi
done

printf '\n%s\n' "${C_GREEN}PORTAL_PROVISION_OK phases=$ran_text${C_OFF}"
if [ "$ran_text" = "1,2,3,4" ]; then
    write_done_box "Done!  Your Portal has been opened!"
else
    printf '\n%s\n' "${C_GREEN}Stopped after phase(s) $ran_text. Re-run with --phases 1,2,3,4 for the full setup.${C_OFF}"
fi
