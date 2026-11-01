#!/bin/bash
# Double-click to install Vigie on this Mac (see installer/install.sh).
cd "$(dirname "$0")" || exit 1
bash ./installer/install.sh
status=$?
echo ""
echo "You can close this window."
exit $status
