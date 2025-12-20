#!/bin/bash
socat TCP-LISTEN:1337,nodelay,reuseaddr,fork EXEC:"timeout -s KILL 10m ./python3.11 ./chal.py"