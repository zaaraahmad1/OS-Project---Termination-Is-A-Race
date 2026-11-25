#!/bin/bash
# measure_llm_delay.sh --model [small|medium|large] --telemetry-json snap.json [--runs 3]
# Times a local LLM's full kill decision (analysis call + PID-choice call).
# One untimed warm-up call loads the model first; reports the MEDIAN of --runs.
# Answer lengths are capped (analysis 256 tokens, decision 64) for every model,
# since small models at temperature 0 can otherwise loop until timeout.
# The model is unloaded afterwards so the next one gets all the RAM.
# Needs Ollama running and the venv:  source ~/ai-agent-env/bin/activate

MODEL="small"; TELEMETRY_JSON=""; RUNS=3
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434/api/generate}"
while [ $# -gt 0 ]; do
    case "$1" in
        --model) MODEL="$2"; shift 2 ;;
        --telemetry-json) TELEMETRY_JSON="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
case "$MODEL" in
    small)  MODEL_TAG="tinyllama:latest" ;;
    medium) MODEL_TAG="llama3.2:3b" ;;
    large)  MODEL_TAG="llama3.1:8b" ;;
    *) echo "unknown --model: $MODEL (expected small|medium|large)" >&2; exit 2 ;;
esac
if [ -z "$TELEMETRY_JSON" ] || [ ! -f "$TELEMETRY_JSON" ]; then
    echo "usage: $0 --model [small|medium|large] --telemetry-json <snap.json> [--runs 3]" >&2; exit 2
fi
python3 -c 'import requests' 2>/dev/null || { echo "Activate your venv first: source ~/ai-agent-env/bin/activate" >&2; exit 2; }

python3 - "$MODEL_TAG" "$TELEMETRY_JSON" "$OLLAMA_URL" "$RUNS" << 'PYEOF'
import sys, json, time, statistics, requests
model_tag, telemetry_path, ollama_url, runs = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
telemetry = json.load(open(telemetry_path))

def llm_generate(prompt, max_tokens):
    payload = {"model": model_tag, "prompt": prompt, "stream": False,
               "options": {"temperature": 0.0, "num_predict": max_tokens, "repeat_penalty": 1.1}}
    try:
        r = requests.post(ollama_url, json=payload, timeout=900)
    except requests.exceptions.ConnectionError:
        sys.exit(f"cannot reach Ollama at {ollama_url} -- is it running? (ollama serve)")
    if r.status_code != 200:
        sys.exit(f"Ollama error {r.status_code}: {r.text[:200]}")
    return r.json().get("response", "")

analysis_prompt = f"""
You are an OS security telemetry agent. Analyze the following processes.
Identify any process that looks like it is rapidly forking children or
resisting termination (fork-respawn racing, double-fork escape, session
hopping, or paired watchdogs). If normal, output ONLY 'STATUS: NORMAL'.
If anomalous, name the offending PID.

Telemetry:
{json.dumps(telemetry, indent=2)}
"""

def decide():
    t0 = time.time()
    analysis = llm_generate(f"[snapshot {time.time_ns()}]" + analysis_prompt, 256).strip()
    reason_prompt = f"""
Based on this anomaly analysis, name the PID to terminate.
Output EXACTLY: {{"target_pid": <PID>}}

Analysis:
{analysis}
"""
    raw = llm_generate(reason_prompt, 64)
    try:
        action = json.loads(raw[raw.find("{"):raw.rfind("}") + 1]).get("target_pid", "none")
    except Exception:
        action = "parse_error"
    return int((time.time() - t0) * 1000), analysis, action

print(f"# {model_tag}: warm-up call (loads the model, not timed)...", file=sys.stderr, flush=True)
llm_generate("Reply with OK.", 8)
times = []
for i in range(1, runs + 1):
    ms, analysis, action = decide()
    times.append(ms)
    print(f"# run {i}/{runs}: {ms} ms, target_pid={action}, analysis={analysis[:100]!r}", file=sys.stderr, flush=True)
print(f"# {model_tag}: median {int(statistics.median(times))} ms over {runs} runs (min {min(times)}, max {max(times)})", file=sys.stderr)
print(f"DELAY_MS {int(statistics.median(times))}", flush=True)
try:
    requests.post(ollama_url, json={"model": model_tag, "keep_alive": 0}, timeout=60)
except Exception:
    pass
PYEOF
