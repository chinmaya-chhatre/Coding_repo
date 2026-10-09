#!/bin/sh
# Start HookScope as the unprivileged `hookscope` user.
#
# Hosted volumes (Fly.io volumes, Render disks) are mounted owned by root, so when the
# container starts as root we first hand the database directory to `hookscope`, then drop
# privileges. Started as any other user, it just runs the app.
set -ef  # -f: no globbing, so the "*" below reaches uvicorn literally

data_dir="$(dirname "${HOOKSCOPE_DB:-/data/hookscope.db}")"
cmd="uvicorn hookscope.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=*"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$data_dir"
    chown hookscope:hookscope "$data_dir"
    # shellcheck disable=SC2086
    exec setpriv --reuid=hookscope --regid=hookscope --init-groups $cmd
fi
# shellcheck disable=SC2086
exec $cmd
