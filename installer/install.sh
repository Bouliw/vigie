#!/usr/bin/env bash
# Installs Vigie for this user on macOS or Linux, from the folder this script sits in:
# its own Python environment in the user's data folder, the Vigie icon, then the app.
# Running it again upgrades Vigie in place. Everything it does is written to install.log.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "$HERE/.." && pwd)"
case "$(uname -s)" in
    Darwin) OS=macos; DEFAULT_DATA="$HOME/Library/Application Support/Vigie" ;;
    *) OS=linux; DEFAULT_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/vigie" ;;
esac
DATA="${VIGIE_DATA_DIR:-$DEFAULT_DATA}"
VENV="$DATA/venv"
LOG="$DATA/install.log"
PYTHON_PAGE="https://www.python.org/downloads/"

say() { printf '%s\n' "$*"; }
step() { printf '\n  %s\n' "$*"; }
log() { printf '%s\n' "$*" >>"$LOG"; }

# Run a command with its output in the log only.
quietly() {
    log "\$ $*"
    "$@" >>"$LOG" 2>&1
}

# The first Python 3.10 or later found, with the venv module. Prints its path.
# The system Python always runs with -I (isolated): a broken package in the user's
# site-packages or a PYTHON* variable cannot get in the way of the install.
# (VIGIE_PYTHON_CANDIDATES replaces the list, for tests.)
find_python() {
    local candidate path candidates
    candidates="${VIGIE_PYTHON_CANDIDATES:-/Library/Frameworks/Python.framework/Versions/Current/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3 python}"
    for candidate in $candidates; do
        path="$(command -v "$candidate" 2>/dev/null)" || continue
        # On a Mac without the developer tools, /usr/bin/python3 only offers to install them.
        if [ "$OS" = macos ] && [ "$path" = /usr/bin/python3 ] && ! xcode-select -p >/dev/null 2>&1; then
            continue
        fi
        if "$path" -I -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
            >/dev/null 2>&1; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

# A Python that is recent enough but cannot make environments (Debian, Ubuntu: python3-venv).
python_without_venv() {
    local path
    path="$(command -v python3 2>/dev/null)" || return 1
    "$path" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1 &&
        ! "$path" -I -c 'import venv, ensurepip' >/dev/null 2>&1
}

open_page() {
    if [ "$OS" = macos ]; then
        open "$1" >/dev/null 2>&1 || true
    else
        xdg-open "$1" >/dev/null 2>&1 || true
    fi
}

fail() {
    say ""
    say "  $1"
    say "  The details are in this file: $LOG"
    say "  If you ask for help, share that file."
    exit 1
}

main() {
    mkdir -p "$DATA" || { say "Vigie cannot write to $DATA."; exit 1; }
    log ""
    log "=== $(date) install from $PROJECT"

    say "Installing Vigie, the log analyzer."
    step "1/4  Looking for Python 3.10 or later..."
    local python
    if ! python="$(find_python)"; then
        if python_without_venv; then
            say "  Python is here, but without the part that makes environments."
            say "  Install it, then run this installer again:"
            say "      sudo apt install python3-venv     (Debian, Ubuntu)"
            exit 1
        fi
        say ""
        say "  Vigie needs Python 3.10 or later, and this computer does not have it yet."
        say "  1. The Python download page opens in your browser: download Python and install it."
        say "  2. Then double-click this installer again."
        log "no suitable Python found"
        open_page "$PYTHON_PAGE"
        exit 1
    fi
    say "  Found $("$python" -I -c 'import platform; print("Python", platform.python_version())'): $python"
    log "python: $python"

    step "2/4  Preparing Vigie's own Python environment..."
    if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import sys' >/dev/null 2>&1; then
        say "  Updating the one already in $VENV"
    else
        rm -rf "$VENV"
        quietly "$python" -I -m venv "$VENV" || fail "Vigie could not create its Python environment."
        say "  Created in $VENV"
    fi

    step "3/4  Installing Vigie (this can take a minute)..."
    quietly "$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade "$PROJECT" ||
        fail "Vigie could not be installed. Check the internet connection, then try again."
    # The same version number from a newer download: install its files anyway.
    quietly "$VENV/bin/python" -m pip install --disable-pip-version-check --force-reinstall --no-deps "$PROJECT" ||
        fail "Vigie could not be installed."
    say "  Vigie $("$VENV/bin/python" -c 'import vigie; print(vigie.__version__)') is installed."

    step "4/4  Adding the Vigie icon..."
    if quietly "$VENV/bin/python" -m vigie shortcut; then
        if [ "$OS" = macos ]; then
            say "  Vigie.app is on your Desktop."
        else
            say "  Vigie is in your applications menu, and on your Desktop if you have one."
        fi
    else
        say "  The icon could not be added (see $LOG); Vigie still works."
    fi

    if [ "${VIGIE_INSTALL_NO_LAUNCH:-}" != 1 ]; then
        say ""
        say "  Opening Vigie in your browser..."
        log "\$ $VENV/bin/python -m vigie ui (in the background)"
        nohup "$VENV/bin/python" -m vigie ui >>"$LOG" 2>&1 &
    fi
    say ""
    say "  Done. Next time, double-click the Vigie icon."
    say "  To remove Vigie, double-click the Uninstall Vigie file next to this one."
}

if [ "${VIGIE_INSTALLER_SOURCE_ONLY:-}" != 1 ]; then
    main "$@"
fi
