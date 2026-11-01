#!/bin/bash
# Double-click to remove Vigie from this Mac (see installer/uninstall.sh).
cd "$(dirname "$0")" || exit 1
bash ./installer/uninstall.sh
status=$?
echo ""
echo "You can close this window."
exit $status
