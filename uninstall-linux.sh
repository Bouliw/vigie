#!/usr/bin/env bash
# Run (or double-click, then "Run in Terminal") to remove Vigie for this user.
cd "$(dirname "$0")" || exit 1
bash ./installer/uninstall.sh
status=$?
if [ -t 0 ] && [ -z "${VIGIE_INSTALL_NO_PAUSE:-}" ]; then
    read -r -p "Press Enter to close." _
fi
exit $status
