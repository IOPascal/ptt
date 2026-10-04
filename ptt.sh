#!/bin/sh
# PTT starter: runs the tool from this checkout, no installation needed.
PTT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHONPATH="$PTT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH
exec python3 -m ptt "$@"
