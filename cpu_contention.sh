#!/bin/bash
#
# cpu_contention.sh --level [idle|medium|high]
#
# Generates a fixed CPU-load preset in the background and prints the
# PIDs it started (one per line), so the harness can track and kill
# them at the end of a run. "idle" starts nothing.
#
# medium/high just run busy `yes > /dev/null` loops, each pinned to one
# core via taskset where available, as a simple, reproducible way to
# make N cores busy regardless of what CPU the grading machine has.

LEVEL="idle"
while [ $# -gt 0 ]; do
    case "$1" in
        --level) LEVEL="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

NCPU=$(nproc)

case "$LEVEL" in
    idle)
        # nothing to start
        ;;
    medium)
        N=$(( NCPU / 2 ))
        [ "$N" -lt 1 ] && N=1
        for i in $(seq 1 "$N"); do
            if command -v taskset >/dev/null 2>&1; then
                taskset -c "$((i % NCPU))" yes > /dev/null 2>&1 &
            else
                yes > /dev/null 2>&1 &
            fi
            echo $!
        done
        ;;
    high)
        for i in $(seq 1 "$NCPU"); do
            if command -v taskset >/dev/null 2>&1; then
                taskset -c "$((i % NCPU))" yes > /dev/null 2>&1 &
            else
                yes > /dev/null 2>&1 &
            fi
            echo $!
        done
        ;;
    *)
        echo "unknown level: $LEVEL (expected idle|medium|high)" >&2
        exit 2
        ;;
esac
