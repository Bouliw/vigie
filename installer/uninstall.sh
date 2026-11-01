#!/usr/bin/env bash
# Removes what the Vigie installer added for this user: its Python environment and the icon.
# The reports made in the app stay where they are, unless the user deletes them.
set -u

case "$(uname -s)" in
    Darwin) OS=macos; DEFAULT_DATA="$HOME/Library/Application Support/Vigie" ;;
    *) OS=linux; DEFAULT_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/vigie" ;;
esac
DATA="${VIGIE_DATA_DIR:-$DEFAULT_DATA}"
VENV="$DATA/venv"

say() { printf '%s\n' "$*"; }

say "Removing Vigie."
if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -m vigie shortcut --remove >/dev/null 2>&1; then
    say "  The Vigie icon is removed."
else
    # Without a working environment, remove the icons Vigie makes, and only those.
    for app in "$HOME/Desktop/Vigie.app" "$HOME/Applications/Vigie.app"; do
        if [ -d "$app" ] && grep -q "io.github.bouliw.vigie" "$app/Contents/Info.plist" 2>/dev/null; then
            rm -rf "$app" && say "  Removed $app"
        fi
    done
    for entry in "$HOME/Desktop/vigie.desktop" "${XDG_DATA_HOME:-$HOME/.local/share}/applications/vigie.desktop"; do
        if [ -f "$entry" ] && grep -q -- "-m vigie ui" "$entry"; then
            rm -f "$entry" && say "  Removed $entry"
        fi
    done
fi
if [ -d "$VENV" ]; then
    rm -rf "$VENV" && say "  Vigie's Python environment is removed."
else
    say "  Vigie's Python environment was not there."
fi
say ""
say "  Done. Your reports are still in: $DATA"
say "  Delete that folder too if you do not need them any more."
