#!/bin/bash
echo "READY"

socat -d -d TCP-LISTEN:8081,reuseaddr,fork \
EXEC:"env LD_LIBRARY_PATH=/srv/app /srv/app/run"
