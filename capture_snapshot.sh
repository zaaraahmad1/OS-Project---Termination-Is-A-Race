#!/bin/bash
#
# capture_snapshot.sh --technique [respawn|doublefork|hop|watchdog] \
#                     [--fork-rate 10] [--seconds 2] [--out snap.json]
#
# Runs one attack briefly, records what the system's process list looks
# like while it is running, then kills the attack. The result is the
# "telemetry" that measure_llm_delay.sh shows to the LLM, so the model's
# decision time is measured on a realistic snapshot of this project's
# attacks.
#
# Does not need sudo.

TECHNIQUE="respawn"
FORK_RATE=10
SECONDS_RUN=2
OUT="snap.json"

while [ $# -gt 0 ]; do
    case "$1" in
        --technique) TECHNIQUE="$2"; shift 2 ;;
        --fork-rate) FORK_RATE="$2"; shift 2 ;;
        --seconds) SECONDS_RUN="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/red_team/$TECHNIQUE"
[ -x "$BIN" ] || { echo "attack binary not found: $BIN (run: make -C red_team)" >&2; exit 2; }

TAG="snapshot_$$"
setsid "$BIN" --fork-rate "$FORK_RATE" --duration $((SECONDS_RUN + 5)) --tag "$TAG" </dev/null >/dev/null 2>&1 &
disown $! 2>/dev/null
sleep "$SECONDS_RUN"

# newest processes first: what a process-creation monitor would show
PS_OUT=$(ps -eo pid=,ppid=,pgid=,sid=,pcpu=,pmem=,stat=,comm= --sort=-start_time)

# kill repeatedly: a forking attack can create a new process while we
# are killing the old ones (the very race this project studies)
for i in $(seq 1 20); do
    pkill -9 -f -- "--tag ${TAG}\$" || break
    sleep 0.1
done

printf '%s\n' "$PS_OUT" | python3 -c '
import sys, json, collections
EXCLUDE = {"ollama", "llama-server", "ps", "python3", "capture_snapsho", "sleep"}
procs = []
for line in sys.stdin:
    f = line.split(None, 7)
    if len(f) < 8 or f[7].strip() in EXCLUDE or f[6].startswith("Z"):
        continue
    procs.append({"pid": int(f[0]), "ppid": int(f[1]), "pgid": int(f[2]), "sid": int(f[3]),
                  "cpu_percent": float(f[4]), "memory_percent": float(f[5]),
                  "state": f[6], "name": f[7].strip()})
mem = {}
for l in open("/proc/meminfo"):
    k, v = l.split(":")
    if k in ("MemTotal", "MemAvailable"):
        mem[k] = v.strip()
counts = collections.Counter(p["name"] for p in procs)
snap = {"memory_status": mem,
        "process_count_by_name": dict(counts.most_common(10)),
        "top_processes": procs[:30]}
json.dump(snap, open(sys.argv[1], "w"), indent=2)
print(f"wrote {sys.argv[1]}: {len(procs)} processes, top names {counts.most_common(3)}")
' "$OUT"
