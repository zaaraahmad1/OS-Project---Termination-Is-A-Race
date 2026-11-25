#!/bin/bash
#
# run_matrix.sh -- runs the whole experiment plan with one command.
#
#   sudo ./run_matrix.sh [--phases A,B,C,D,E,F] [--reps 3] [--timeout-s 10]
#                        [--delay-small MS --delay-medium MS --delay-large MS]
#                        [--results-dir results] [--operator Zaara] [--dry-run]
#
# Phases (each writes its own CSV in --results-dir):
#   A  baseline     all 4 attacks x all 7 strategies, fork rate 10,
#                   idle CPU, no delay                      -> H1, H2, H3
#   B  fork rate    fork rate 2 and 50 (10 comes from A)    -> H1
#   C  CPU load     medium and high CPU (idle comes from A) -> scheduling
#   D  delay        the three measured LLM delays (0 from A)-> H4
#                   (skipped unless all three --delay-* are given)
#   E  benign       benign processes share the attacker's
#                   group/cgroup                            -> H5
#   F  targeting    detector flags the NEWEST process
#                   instead of the parent                   -> sensitivity
#
# Resumable: every configuration checks its CSV first and only runs the
# repetitions that are missing. If the run is interrupted (Ctrl-C, laptop
# sleeps, WSL restarts), just run the same command again.
#
# Why --timeout-s 10 (instead of the harness default of 60): in testing,
# every successful kill cleared in well under 1 second, and none of the
# four attacks ever dies on its own, so a run that has not cleared after
# 10 seconds will not clear at all. Failures cost the full timeout, so this
# is what keeps the whole matrix to roughly an hour.
#
# --dry-run lists every configuration and an estimated time, runs nothing.

set -u

PHASES="A,B,C,D,E,F"
REPS=3
TIMEOUT_S=10
DELAY_SMALL=""
DELAY_MEDIUM=""
DELAY_LARGE=""
RESULTS_DIR="results"
OPERATOR="Zaara"
DRY_RUN=0
EXTRA=()   # passed straight through to run_harness.sh (e.g. --cgroup-base)

while [ $# -gt 0 ]; do
    case "$1" in
        --phases) PHASES="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        --timeout-s) TIMEOUT_S="$2"; shift 2 ;;
        --delay-small) DELAY_SMALL="$2"; shift 2 ;;
        --delay-medium) DELAY_MEDIUM="$2"; shift 2 ;;
        --delay-large) DELAY_LARGE="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --operator) OPERATOR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --cgroup-base) EXTRA+=(--cgroup-base "$2"); shift 2 ;;
        -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$SCRIPT_DIR/run_harness.sh"

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "run_matrix.sh must run as root:  sudo $0 ..." >&2
    exit 2
fi

ALL_TECH="respawn doublefork hop watchdog"
ALL_STRAT="pid pgrp tree stopkill pidfd cgroup cgroup_early"

# ---------- build the list of configurations ----------
# one line per config:  phase technique strategy fork cpu delay llm target share pids_max
CONFIGS=()
add() { CONFIGS+=("$*"); }
want() { [[ ",$PHASES," == *",$1,"* ]]; }

if want A; then
    for t in $ALL_TECH; do for s in $ALL_STRAT; do
        add A $t $s 10 idle 0 off parent 0 500
    done; done
fi
if want B; then
    for t in respawn doublefork watchdog; do for s in pid tree stopkill cgroup; do for f in 2 50; do
        add B $t $s $f idle 0 off parent 0 500
    done; done; done
fi
if want C; then
    for t in $ALL_TECH; do for s in tree stopkill cgroup; do for c in medium high; do
        add C $t $s 10 $c 0 off parent 0 500
    done; done; done
fi
if want D; then
    if [ -z "$DELAY_SMALL" ] || [ -z "$DELAY_MEDIUM" ] || [ -z "$DELAY_LARGE" ]; then
        echo "[matrix] phase D skipped: give --delay-small, --delay-medium and --delay-large (from measure_llm_delay.sh)"
    else
        for t in respawn doublefork; do for s in pgrp tree cgroup cgroup_early; do
            for pair in "small:$DELAY_SMALL" "medium:$DELAY_MEDIUM" "large:$DELAY_LARGE"; do
                # doublefork keeps every grandchild, so a long delay needs a higher cap
                add D $t $s 10 idle "${pair#*:}" "${pair%%:*}" parent 0 2000
            done
        done; done
    fi
fi
if want E; then
    for t in $ALL_TECH; do for s in pid pgrp tree cgroup; do
        add E $t $s 10 idle 0 off parent 1 500
    done; done
fi
if want F; then
    for t in $ALL_TECH; do for s in pid tree stopkill cgroup; do
        add F $t $s 10 idle 0 off newest 0 500
    done; done
fi

csv_for() {
    case "$1" in
        A) echo "$RESULTS_DIR/A_baseline.csv" ;;
        B) echo "$RESULTS_DIR/B_fork_rate.csv" ;;
        C) echo "$RESULTS_DIR/C_cpu_load.csv" ;;
        D) echo "$RESULTS_DIR/D_delay.csv" ;;
        E) echo "$RESULTS_DIR/E_benign_share.csv" ;;
        F) echo "$RESULTS_DIR/F_target_newest.csv" ;;
    esac
}

# how many reps of this exact configuration are already in its CSV
done_reps() {  # csv technique strategy fork cpu delay target share
    [ -f "$1" ] || { echo 0; return; }
    awk -F, -v t="$2" -v s="$3" -v f="$4" -v c="$5" -v d="$6" -v g="$7" -v b="$8" \
        'NR>1 && $3==t && $4==s && $5==f && $6==c && $8==d && $15==g && $16==b {n++} END{print n+0}' "$1"
}

# ---------- plan + time estimate ----------
TOTAL_RUNS=0; TODO_RUNS=0; WORST_S=0
for cfg in "${CONFIGS[@]}"; do
    read -r ph t s f c d l g b pm <<< "$cfg"
    have=$(done_reps "$(csv_for "$ph")" "$t" "$s" "$f" "$c" "$d" "$g" "$b")
    need=$(( REPS - have )); [ "$need" -lt 0 ] && need=0
    TOTAL_RUNS=$((TOTAL_RUNS + REPS)); TODO_RUNS=$((TODO_RUNS + need))
    # worst case per run: settle + delay + full timeout + teardown
    WORST_S=$(( WORST_S + need * (2 + d/1000 + TIMEOUT_S) ))
    [ "$DRY_RUN" -eq 1 ] && printf '%s  %-10s %-12s fork=%-3s cpu=%-6s delay=%-6s target=%-6s share=%s  (%s/%s done)\n' \
        "$ph" "$t" "$s" "$f" "$c" "$d" "$g" "$b" "$have" "$REPS"
done
echo "[matrix] ${#CONFIGS[@]} configurations x $REPS reps = $TOTAL_RUNS runs; $TODO_RUNS still to run"
echo "[matrix] estimated time: about $(( WORST_S * 55 / 100 / 60 )) min (at most $(( WORST_S / 60 )) min if every run failed)"
[ "$DRY_RUN" -eq 1 ] && exit 0
[ "$TODO_RUNS" -eq 0 ] && { echo "[matrix] nothing to do -- all results present"; exit 0; }

mkdir -p "$RESULTS_DIR"
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER": "$RESULTS_DIR"
LOG="$RESULTS_DIR/matrix_$(date +%Y%m%d_%H%M%S).log"
[ -n "${SUDO_USER:-}" ] && { touch "$LOG"; chown "$SUDO_USER": "$LOG"; }
trap 'echo; echo "[matrix] interrupted -- run the same command again to resume"; exit 130' INT TERM

# ---------- run ----------
START=$(date +%s); DONE=0
for cfg in "${CONFIGS[@]}"; do
    read -r ph t s f c d l g b pm <<< "$cfg"
    CSV=$(csv_for "$ph")
    have=$(done_reps "$CSV" "$t" "$s" "$f" "$c" "$d" "$g" "$b")
    need=$(( REPS - have ))
    [ "$need" -le 0 ] && continue
    SHARE_ARG=(); [ "$b" = "1" ] && SHARE_ARG=(--benign-share)
    printf '[matrix] %s  %-10s %-12s fork=%-3s cpu=%-6s delay=%-6s target=%-6s share=%s  reps %s-%s ... ' \
        "$ph" "$t" "$s" "$f" "$c" "$d" "$g" "$b" "$((have + 1))" "$REPS"
    "$HARNESS" --technique "$t" --strategy "$s" --fork-rate "$f" --cpu-load "$c" \
        --delay-ms "$d" --llm-mode "$l" --target "$g" "${SHARE_ARG[@]}" \
        --reps "$need" --rep-start "$((have + 1))" --pids-max "$pm" --timeout-s "$TIMEOUT_S" \
        --operator "$OPERATOR" --results-csv "$CSV" "${EXTRA[@]}" >> "$LOG" 2>&1
    rc=$?
    DONE=$((DONE + need))
    # show this config's results, e.g. "erad 3/3"
    erad=$(awk -F, -v t="$t" -v s="$s" -v f="$f" -v c="$c" -v d="$d" -v g="$g" -v b="$b" \
        'NR>1 && $3==t && $4==s && $5==f && $6==c && $8==d && $15==g && $16==b {n++; e+=$9; v+=(1-$17)} END{printf "erad %d/%d%s", e, n, (v>0 ? "  INVALID ROWS: " v : "")}' "$CSV")
    [ "$rc" -ne 0 ] && erad="$erad  (harness exit $rc -- see $LOG)"
    echo "$erad   [$DONE/$TODO_RUNS, $(( ($(date +%s) - START) / 60 )) min]"
done

echo "[matrix] finished in $(( ($(date +%s) - START) / 60 )) min. CSVs in $RESULTS_DIR/, full log: $LOG"
echo "[matrix] next:  python3 summarize_results.py --results-dir $RESULTS_DIR"
