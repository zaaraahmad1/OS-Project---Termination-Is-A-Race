#!/bin/bash
#
# benign_workload.sh --count <N>
#
# Starts N innocent background processes that look superficially like
# real work (a tight CPU loop), so a broad termination strategy
# (pgrp / cgroup) has something nearby it COULD wrongly kill if it
# overreaches. Prints one PID per line so the harness can check
# survival afterward and clean up.
#
# These are plain bash loops, so count_survivors.sh (which matches the
# attack programs' command lines) never confuses them with the attacker.
# Started from here, they share no session, process group or cgroup with
# the attacker. For the Hypothesis 5 condition where benign work DOES
# share the attacker's group, run_harness.sh --benign-share starts them
# inside the attacker's group itself instead of calling this script.

N=3
while [ $# -gt 0 ]; do
    case "$1" in
        --count) N="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

for i in $(seq 1 "$N"); do
    # stdin/stdout/stderr MUST be detached from this script's own fds:
    # this script's output is read via command substitution by the
    # caller, and an infinite loop that inherits that pipe's write end
    # would hold it open forever, hanging the caller indefinitely.
    ( while true; do : $((1+1)); done ) < /dev/null > /dev/null 2>&1 &
    echo $!
done
