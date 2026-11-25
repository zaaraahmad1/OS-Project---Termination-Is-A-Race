#!/bin/bash
#
# count_survivors.sh --tag <STRING>
#
# Ground truth for every run: counts the attacker processes that are
# still alive for one run's tag. It looks at the system directly and
# never trusts what the defender says it did.
#
# Output (stdout):
#   SURVIVORS <count>
#   PID <pid1>
#   PID <pid2>
#   ...
# Exit code: always 0 (zero survivors is a result, not an error).
#
# HOW A PROCESS IS IDENTIFIED (and why not the environment tag)
# -------------------------------------------------------------
# The project plan said to look for the tag in /proc/<pid>/environ. That
# cannot work: the attacks set it with setenv("MARK", tag, 1) AFTER they
# start, which only changes the copy of the environment in the process's
# heap. /proc/<pid>/environ always shows the ORIGINAL environment from
# exec time, so the tag never appears there.
#
# What does work is the command line. None of the four attacks ever calls
# exec() again, so every forked child, orphaned grandchild (doublefork),
# hopped child (hop) and respawned partner (watchdog) keeps the exact
# command line of the original program:
#     /path/to/red_team/<attack> --fork-rate N --duration S --tag <TAG>
# We match that with pgrep (fast: a few ms even with hundreds of
# processes). The pattern is anchored at both ends, so:
#   * the tag must be the LAST argument  -> run "..._1" never matches
#     run "..._10"
#   * the program must be the FIRST word -> wrapper shells, setsid, or
#     this script itself (whose own command line contains "--tag") never
#     match
# Zombies (killed, waiting to be reaped) have an empty command line, so
# they are correctly NOT counted as survivors. Stopped (SIGSTOP)
# processes ARE counted: they are still alive.

TAG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$TAG" ]; then
    echo "usage: $0 --tag <STRING>" >&2
    exit 2
fi

PATTERN="^[^ ]*/red_team/(respawn|doublefork|hop|watchdog) .*--tag ${TAG}\$"

PIDS=$(pgrep -f -- "$PATTERN")
COUNT=$(printf '%s\n' "$PIDS" | grep -c '^[0-9]')

echo "SURVIVORS $COUNT"
for p in $PIDS; do
    echo "PID $p"
done
