#!/bin/bash
echo "READY"
socat TCP-LISTEN:8080,nodelay,reuseaddr,fork EXEC:"timeout -s KILL 10m /srv/app/ld-linux-x86-64.so.2 --library-path /srv/app /srv/app/run"
