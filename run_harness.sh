#!/bin/bash
#
# run_harness.sh -- runs one experiment configuration for N reps and
# appends one CSV row per rep.
#
#   sudo ./run_harness.sh --technique T --strategy S \
#        [--fork-rate 10] [--cpu-load idle|medium|high] \
#        [--delay-ms 0] [--llm-mode off|small|medium|large] \
#        [--target parent|newest] [--benign-count 3] [--benign-share] \
#        [--reps 3] [--rep-start 1] [--pids-max 500] [--timeout-s 60] [--settle-ms 300] \
#        [--operator Zaara] [--results-csv results.csv] \
#        [--cgroup-base /sys/fs/cgroup/harness_run]
#
# Must run as root (sudo): creating cgroups, setting pids.max and
# cgroup.kill all need it.
#
# Strategies: pid | pgrp | tree | stopkill | pidfd | cgroup | cgroup_early
#   cgroup        detect -> wait for the inference delay -> move suspect
#                 into a quarantine cgroup -> freeze -> kill
#   cgroup_early  detect -> move suspect into quarantine IMMEDIATELY ->
#                 wait for the inference delay -> freeze -> kill
#                 (tests the exception in Hypothesis 4)
#
# --target: which PID the simulated detector flags
#   parent  (default) the attack's original process -- "the malicious
#           program" a detector identifies. This is what makes the
#           strategies differ in an informative way.
#   newest  the most recently created tagged process (highest PID) --
#           the process that is "currently active". Descendant-based
#           strategies can never reach UP to the parent from here, so
#           almost everything fails against respawn/hop/watchdog. Useful
#           as a sensitivity check, not as the main setting.
#
# --benign-share: start the benign processes INSIDE the attacker's own
#   session, process group and cgroup (as children of the attacker's
#   first process), instead of separately. This is the condition
#   Hypothesis 5 is about: does a broad strategy take innocent work down
#   with the malware when they share a group?
#
# Per-rep sequence (times are relative to "detection"):
#   1. fresh capped cgroup (pids.max) for this rep
#   2. CPU contention preset
#   3. benign workload (separate, unless --benign-share)
#   4. attacker started in its OWN session + process group, inside the
#      capped cgroup from its very first instruction
#   5. wait --settle-ms (the attack runs undetected), then DETECTION:
#      pick the target PID
#   6. [cgroup_early only] quarantine the suspect now
#   7. wait --delay-ms (the defender "thinking")
#   8. snapshot the attacker's live PIDs, then KILL (defender binary)
#   9. poll survivors until 0 or --timeout-s after the kill
#  10. record eradicated / time_to_clear_ms / respawns / benign harm
#  11. tear everything down so one rep can never leak into the next
#
# CSV columns (the proposal plan's 14, then 5 added at the end):
#   run_id,timestamp,technique,strategy,fork_rate,cpu_load,llm_mode,
#   delay_ms,eradicated,time_to_clear_ms,respawns,benign_killed,
#   benign_total,operator,target,benign_share,valid,alive_at_kill,
#   survivors_at_end
#   time_to_clear_ms  from the kill being issued to 0 survivors (the
#                     delay is NOT included); blank if never cleared
#   respawns          tagged PIDs seen after the kill that did not exist
#                     at the moment of the kill
#   valid             0 if the strategy could not actually be applied
#                     (e.g. defender had to fall back) -- exclude these
#   alive_at_kill     attacker processes alive when the kill was issued
#                     (shows how far the attack spread during the delay)
#   survivors_at_end  attacker processes still alive at the timeout
#                     (0 when eradicated; shows partial success)

set -u
ORIG_ARGS="$*"

TECHNIQUE=""
STRATEGY=""
FORK_RATE=10
CPU_LOAD="idle"
DELAY_MS=0
LLM_MODE="off"
TARGET_MODE="parent"
BENIGN_COUNT=3
BENIGN_SHARE=0
REPS=3
REP_START=1
PIDS_MAX=500
TIMEOUT_S=60
SETTLE_MS=300
OPERATOR="Zaara"
RESULTS_CSV="results.csv"
CGROUP_BASE="/sys/fs/cgroup/harness_run"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_DIR="$SCRIPT_DIR/red_team"
DEFENDER_BIN="$SCRIPT_DIR/defender"
COUNTER="$SCRIPT_DIR/count_survivors.sh"
CPU_GEN="$SCRIPT_DIR/cpu_contention.sh"
BENIGN_GEN="$SCRIPT_DIR/benign_workload.sh"

HEADER="run_id,timestamp,technique,strategy,fork_rate,cpu_load,llm_mode,delay_ms,eradicated,time_to_clear_ms,respawns,benign_killed,benign_total,operator,target,benign_share,valid,alive_at_kill,survivors_at_end"
ATTACK_PATTERN="^[^ ]*/red_team/(respawn|doublefork|hop|watchdog) "

usage() {
    sed -n '3,13p' "$0" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --technique) TECHNIQUE="$2"; shift 2 ;;
        --strategy) STRATEGY="$2"; shift 2 ;;
        --fork-rate) FORK_RATE="$2"; shift 2 ;;
        --cpu-load) CPU_LOAD="$2"; shift 2 ;;
        --delay-ms) DELAY_MS="$2"; shift 2 ;;
        --llm-mode) LLM_MODE="$2"; shift 2 ;;
        --target) TARGET_MODE="$2"; shift 2 ;;
        --benign-count) BENIGN_COUNT="$2"; shift 2 ;;
        --benign-share) BENIGN_SHARE=1; shift ;;
        --reps) REPS="$2"; shift 2 ;;
        --rep-start) REP_START="$2"; shift 2 ;;
        --pids-max) PIDS_MAX="$2"; shift 2 ;;
        --timeout-s) TIMEOUT_S="$2"; shift 2 ;;
        --settle-ms) SETTLE_MS="$2"; shift 2 ;;
        --operator) OPERATOR="$2"; shift 2 ;;
        --results-csv) RESULTS_CSV="$2"; shift 2 ;;
        --cgroup-base) CGROUP_BASE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

# ---------- validate ----------
case "$TECHNIQUE" in respawn|doublefork|hop|watchdog) ;; *) echo "--technique must be respawn|doublefork|hop|watchdog" >&2; usage ;; esac
case "$STRATEGY" in pid|pgrp|tree|stopkill|pidfd|cgroup|cgroup_early) ;; *) echo "--strategy must be pid|pgrp|tree|stopkill|pidfd|cgroup|cgroup_early" >&2; usage ;; esac
case "$TARGET_MODE" in parent|newest) ;; *) echo "--target must be parent|newest" >&2; exit 2 ;; esac
case "$CPU_LOAD" in idle|medium|high) ;; *) echo "--cpu-load must be idle|medium|high" >&2; exit 2 ;; esac
case "$LLM_MODE" in off|small|medium|large) ;; *) echo "--llm-mode must be off|small|medium|large" >&2; exit 2 ;; esac
for v in FORK_RATE DELAY_MS BENIGN_COUNT REPS REP_START PIDS_MAX TIMEOUT_S SETTLE_MS; do
    if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then echo "$v must be a whole number (got '${!v}')" >&2; exit 2; fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run_harness.sh must run as root (cgroups need it):  sudo $0 $ORIG_ARGS" >&2
    exit 2
fi
if [ ! -x "$ATTACK_DIR/$TECHNIQUE" ]; then
    echo "attack binary not found: $ATTACK_DIR/$TECHNIQUE  (run: make -C red_team)" >&2; exit 2
fi
if [ ! -x "$DEFENDER_BIN" ]; then
    echo "defender binary not found: $DEFENDER_BIN  (run: gcc -Wall defender.c -o defender)" >&2; exit 2
fi

# ---------- cgroup setup ----------
CG_PARENT="$(dirname "$CGROUP_BASE")"
QUAR_ROOT="$CG_PARENT/quarantine"
if [ ! -f "$CG_PARENT/cgroup.controllers" ]; then
    echo "ERROR: $CG_PARENT is not a cgroup v2 directory. Check 'mount | grep cgroup2' and pass --cgroup-base <cgroup2-mount>/harness_run" >&2
    exit 2
fi
# cgroup v2 only lets a child cgroup use a controller that its parent has
# switched on in cgroup.subtree_control
if grep -qw pids "$CG_PARENT/cgroup.controllers" && ! grep -qw pids "$CG_PARENT/cgroup.subtree_control"; then
    wr "+pids" "$CG_PARENT/cgroup.subtree_control" \
        || echo "[harness] WARNING: could not enable the pids controller in $CG_PARENT/cgroup.subtree_control" >&2
fi

# ---------- results file ----------
if [ ! -f "$RESULTS_CSV" ]; then
    echo "$HEADER" > "$RESULTS_CSV"
elif [ "$(head -1 "$RESULTS_CSV")" != "$HEADER" ]; then
    echo "ERROR: $RESULTS_CSV has a different header (old format?). Rename it or use --results-csv <new file>." >&2
    exit 2
fi
# the CSV is created by root; hand it back to the real user so you can edit it
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER": "$RESULTS_CSV" 2>/dev/null

# ---------- helpers ----------
now_ms() { date +%s%3N; }
# write a value to a (cgroup) file; succeed/fail silently
wr() { { echo "$1" > "$2"; } 2>/dev/null; }
sleep_ms() { [ "$1" -gt 0 ] && sleep "$(awk -v m="$1" 'BEGIN{printf "%.3f", m/1000}')"; return 0; }

# alive = exists and is not a zombie (a zombie is already dead)
is_alive() {
    local st
    st=$(awk '{sub(/.*\) /,""); print $1}' "/proc/$1/stat" 2>/dev/null) || return 1
    [ -n "$st" ] && [ "$st" != "Z" ]
}

remove_cgroup() {  # rmdir only works once the kernel has emptied it
    local d="$1" i
    [ -d "$d" ] || return 0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        rmdir "$d" 2>/dev/null && return 0
        wr 1 "$d/cgroup.kill"
        sleep 0.1
    done
    echo "[harness] WARNING: could not remove $d" >&2
}

# clear leftovers from any earlier crashed/interrupted run
pkill -9 -f -- "$ATTACK_PATTERN" 2>/dev/null
for d in "$CG_PARENT"/harness_run_* "$QUAR_ROOT"_*; do [ -d "$d" ] && remove_cgroup "$d"; done

# ---------- reps ----------
for rep in $(seq "$REP_START" $((REP_START + REPS - 1))); do
    RUN_ID="${TECHNIQUE}_${STRATEGY}_${FORK_RATE}_${DELAY_MS}_${rep}"
    TAG="${RUN_ID}_$(date +%s%N)"   # unique per rep, so runs can never be confused
    TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    VALID=1
    echo "=============================================================="
    echo "[harness] run_id=$RUN_ID target=$TARGET_MODE cpu_load=$CPU_LOAD benign_share=$BENIGN_SHARE"

    # 1. capped cgroup for the attacker
    CG="${CGROUP_BASE}_${RUN_ID}"
    remove_cgroup "$CG"
    if mkdir "$CG" 2>/dev/null; then
        if ! wr "$PIDS_MAX" "$CG/pids.max"; then
            echo "[harness] WARNING: pids controller not available -- running WITHOUT the pids.max cap" >&2
        fi
    else
        echo "[harness] WARNING: could not create $CG -- running WITHOUT the pids.max cap" >&2
        CG=""
    fi

    # 2. CPU contention
    CPU_PIDS=$("$CPU_GEN" --level "$CPU_LOAD")

    # 3. benign workload (separate from the attacker unless --benign-share)
    BENIGN_PIDS=""
    if [ "$BENIGN_SHARE" -eq 0 ]; then
        BENIGN_PIDS=$("$BENIGN_GEN" --count "$BENIGN_COUNT")
    fi

    # 4. attacker. setsid gives it its own session + process group (as
    #    real malware launched from anywhere would have), so a
    #    process-group kill can never reach the harness itself. The tiny
    #    bash wrapper joins the capped cgroup, records its PID, optionally
    #    starts the shared benign processes, then exec()s the attack --
    #    so the attacker keeps that PID and every descendant is born
    #    inside the cap.
    PIDFILE=$(mktemp); BENFILE=$(mktemp)
    NSHARE=0; [ "$BENIGN_SHARE" -eq 1 ] && NSHARE="$BENIGN_COUNT"
    setsid bash -c '
        cg="$1"; pidf="$2"; benf="$3"; nben="$4"; shift 4
        [ -n "$cg" ] && echo $$ > "$cg/cgroup.procs" 2>/dev/null
        i=0
        while [ "$i" -lt "$nben" ]; do
            ( while :; do :; done ) </dev/null >/dev/null 2>&1 &
            echo $! >> "$benf"; i=$((i+1))
        done
        echo $$ > "$pidf"
        exec "$@"
    ' _ "$CG" "$PIDFILE" "$BENFILE" "$NSHARE" \
        "$ATTACK_DIR/$TECHNIQUE" --fork-rate "$FORK_RATE" --duration "$((TIMEOUT_S + DELAY_MS/1000 + 30))" --tag "$TAG" \
        < /dev/null > /dev/null 2>&1 &
    disown $! 2>/dev/null   # no "Killed" job messages from bash when it dies

    ROOT_PID=""
    for i in $(seq 1 50); do ROOT_PID=$(cat "$PIDFILE" 2>/dev/null); [ -n "$ROOT_PID" ] && break; sleep 0.05; done
    [ "$BENIGN_SHARE" -eq 1 ] && BENIGN_PIDS=$(cat "$BENFILE")
    rm -f "$PIDFILE" "$BENFILE"
    BENIGN_TOTAL=$(printf '%s\n' "$BENIGN_PIDS" | grep -c '^[0-9]')
    BENIGN_CSV=$(printf '%s\n' "$BENIGN_PIDS" | grep '^[0-9]' | paste -sd, -)

    # 5. the attack runs undetected for --settle-ms, then DETECTION
    sleep_ms "$SETTLE_MS"
    if [ "$TARGET_MODE" = "parent" ]; then
        TARGET_PID="$ROOT_PID"
    else
        TARGET_PID=$("$COUNTER" --tag "$TAG" | awk '/^PID/{print $2}' | sort -n | tail -1)
    fi
    if [ -z "$TARGET_PID" ] || ! is_alive "$TARGET_PID"; then
        echo "[harness] ERROR: attacker did not start for $RUN_ID, skipping rep" >&2
        kill -9 $CPU_PIDS $BENIGN_PIDS 2>/dev/null
        pkill -9 -f -- "--tag ${TAG}\$" 2>/dev/null
        [ -n "$CG" ] && remove_cgroup "$CG"
        continue
    fi
    echo "[harness] attacker root pid=$ROOT_PID, detector flags pid=$TARGET_PID ($TARGET_MODE)"

    # 6. cgroup_early: quarantine at detection time, before "thinking"
    DEF_STRATEGY="$STRATEGY"
    DEF_PHASE="all"
    if [ "$STRATEGY" = "cgroup_early" ]; then
        DEF_STRATEGY="cgroup"
        DEF_PHASE="kill"
        MOVE_OUT=$("$DEFENDER_BIN" --strategy cgroup --phase move --target-pid "$TARGET_PID" \
                    --cgroup-root "$QUAR_ROOT" --llm-mode "$LLM_MODE")
        echo "$MOVE_OUT"
        echo "$MOVE_OUT" | grep -q 'fallback=1' && VALID=0
        # keep the fork-bomb safety cap on the quarantine group too
        wr "$PIDS_MAX" "${QUAR_ROOT}_${TARGET_PID}/pids.max"
    fi

    # 7. the defender "thinks"
    sleep_ms "$DELAY_MS"

    # 8. snapshot, then kill
    PRE_KILL_PIDS=$("$COUNTER" --tag "$TAG" | awk '/^PID/{print $2}')
    PRE_KILL_COUNT=$(printf '%s\n' "$PRE_KILL_PIDS" | grep -c '^[0-9]')
    BENIGN_ARG=(); [ -n "$BENIGN_CSV" ] && BENIGN_ARG=(--benign-pids "$BENIGN_CSV")
    T_KILL=$(now_ms)
    DEF_OUT=$("$DEFENDER_BIN" --strategy "$DEF_STRATEGY" --phase "$DEF_PHASE" --target-pid "$TARGET_PID" \
                --delay-ms 0 --llm-mode "$LLM_MODE" --cgroup-root "$QUAR_ROOT" "${BENIGN_ARG[@]}")
    echo "$DEF_OUT"
    echo "$DEF_OUT" | grep -q 'fallback=1' && VALID=0

    # 9. poll for eradication
    SEEN_PIDS="$PRE_KILL_PIDS"
    RESPAWNS=0
    ERADICATED=0
    TIME_TO_CLEAR_MS=""
    while :; do
        OUT=$("$COUNTER" --tag "$TAG")
        COUNT=$(echo "$OUT" | awk '/^SURVIVORS/{print $2}')
        for p in $(echo "$OUT" | awk '/^PID/{print $2}'); do
            if ! printf '%s\n' "$SEEN_PIDS" | grep -qx "$p"; then
                RESPAWNS=$((RESPAWNS + 1))
                SEEN_PIDS="$SEEN_PIDS
$p"
            fi
        done
        if [ "$COUNT" = "0" ]; then
            ERADICATED=1
            TIME_TO_CLEAR_MS=$(( $(now_ms) - T_KILL ))
            break
        fi
        [ $(( $(now_ms) - T_KILL )) -ge $((TIMEOUT_S * 1000)) ] && break
        sleep 0.05
    done

    # 10. benign harm (short grace period so a SIGKILL already in flight lands)
    sleep 0.2
    BENIGN_KILLED=0
    for p in $BENIGN_PIDS; do
        is_alive "$p" || BENIGN_KILLED=$((BENIGN_KILLED + 1))
    done

    [ "$VALID" -eq 0 ] && echo "[harness] WARNING: strategy could not be applied as requested -- row marked valid=0"
    echo "[harness] eradicated=$ERADICATED time_to_clear_ms=${TIME_TO_CLEAR_MS:-TIMEOUT} respawns=$RESPAWNS benign_killed=$BENIGN_KILLED/$BENIGN_TOTAL alive_at_kill=$PRE_KILL_COUNT survivors_at_end=$COUNT valid=$VALID"
    echo "$RUN_ID,$TS,$TECHNIQUE,$STRATEGY,$FORK_RATE,$CPU_LOAD,$LLM_MODE,$DELAY_MS,$ERADICATED,${TIME_TO_CLEAR_MS},$RESPAWNS,$BENIGN_KILLED,$BENIGN_TOTAL,$OPERATOR,$TARGET_MODE,$BENIGN_SHARE,$VALID,$PRE_KILL_COUNT,$COUNT" >> "$RESULTS_CSV"

    # 11. teardown
    [ -n "$CG" ] && wr 1 "$CG/cgroup.kill"
    pkill -9 -f -- "--tag ${TAG}\$" 2>/dev/null
    kill -9 $CPU_PIDS $BENIGN_PIDS 2>/dev/null
    [ -n "$CG" ] && remove_cgroup "$CG"
    for d in "$QUAR_ROOT"_*; do [ -d "$d" ] && remove_cgroup "$d"; done
    sleep 0.3
done

echo "=============================================================="
echo "[harness] done. Results appended to $RESULTS_CSV"
