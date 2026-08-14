#!/bin/bash

# Wrapper script for Rustnetec macOS app
# Launches the tray helper (--tray): a pure GUI menu-bar icon that spawns
# the capture daemon child itself. No sudo required for the tray UI itself;
# packet capture in the daemon child needs BPF access (access_bpf group) and
# degrades to process-only mode when unavailable.
#
# Logs both processes' output to ~/Library/Logs/rustnet-tray.log so tray
# startup problems can be diagnosed without a terminal attached.

# Get the directory where the app bundle is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

LOG="${HOME}/Library/Logs/rustnet-tray.log"
mkdir -p "$(dirname "$LOG")"

exec "$DIR/rustnetec" --tray "$@" >> "$LOG" 2>&1
