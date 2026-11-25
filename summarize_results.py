#!/usr/bin/env python3
"""
summarize_results.py -- turns the CSVs from run_matrix.sh into tables and
figures for the report.

    python3 summarize_results.py [--results-dir results]

Writes:
    results/summary.md        every table, grouped by hypothesis
    results/figures/*.png     report figures (needs matplotlib; tables are
                              written either way)

Only rows with valid=1 are used; any invalid rows are counted and listed
at the top of summary.md so they can't be missed.
"""
import argparse
import csv
import os
import statistics
import sys
from collections import defaultdict

TECHS = ["respawn", "doublefork", "hop", "watchdog"]
STRATS = ["pid", "pgrp", "tree", "stopkill", "pidfd", "cgroup", "cgroup_early"]
FILES = {
    "A": "A_baseline.csv",
    "B": "B_fork_rate.csv",
    "C": "C_cpu_load.csv",
    "D": "D_delay.csv",
    "E": "E_benign_share.csv",
    "F": "F_target_newest.csv",
}

# reference palette (dataviz skill): categorical slots in fixed order,
# sequential blue ramp, text/grid inks
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
STRAT_COLOR = {s: SERIES[i] for i, s in enumerate(STRATS)}   # colour follows the strategy
STRAT_MARKER = dict(zip(STRATS, ["o", "s", "^", "D", "v", "P", "X"]))  # shape too, never colour alone


def dodge(k, n, span):
    """Small vertical offset so strategies with identical results don't
    hide behind each other (k-th of n series, span = y-axis range)."""
    return (k - (n - 1) / 2) * 0.03 * span


def load(results_dir):
    data, invalid = {}, []
    for ph, name in FILES.items():
        path = os.path.join(results_dir, name)
        if not os.path.exists(path):
            data[ph] = []
            continue
        rows = list(csv.DictReader(open(path)))
        for r in rows:
            if r.get("valid") != "1":
                invalid.append((ph, r["run_id"]))
        data[ph] = [r for r in rows if r.get("valid") == "1"]
    return data, invalid


def pick(rows, **kw):
    return [r for r in rows if all(r[k] == str(v) for k, v in kw.items())]


def erad(rows):
    """'k/n' eradicated out of n, or '-' if no runs."""
    if not rows:
        return "-"
    return f"{sum(int(r['eradicated']) for r in rows)}/{len(rows)}"


def erad_rate(rows):
    return sum(int(r["eradicated"]) for r in rows) / len(rows) if rows else None


def mean(values):
    values = [float(v) for v in values if v not in ("", None)]
    return statistics.mean(values) if values else None


def fmt(x, unit="", digits=0):
    return "-" if x is None else f"{x:.{digits}f}{unit}"


def removed_share(rows):
    """Mean share of the attack's processes the kill removed:
    1 - survivors_at_end / (alive_at_kill + respawns)."""
    vals = []
    for r in rows:
        total = int(r["alive_at_kill"]) + int(r["respawns"])
        if total > 0:
            vals.append(1 - int(r["survivors_at_end"]) / total)
    return statistics.mean(vals) if vals else None


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out) + "\n"


def delay_levels(D):
    """[(label, delay_ms, llm_mode)] in increasing delay, including 0 from A."""
    seen = {(r["llm_mode"], r["delay_ms"]) for r in D}
    levels = sorted(seen, key=lambda x: int(x[1]))
    return [("none", "0", "off")] + [(f"{m} ({int(d)/1000:g} s)", d, m) for m, d in levels]


def build_markdown(data, invalid):
    A, B, C, D, E, F = (data[k] for k in "ABCDEF")
    md = ["# Termination Is a Race: results summary\n"]
    counts = ", ".join(f"{k}: {len(v)}" for k, v in data.items())
    md.append(f"Valid runs per phase: {counts}.  Cells show **eradicated runs / total runs** "
              "unless stated otherwise. Target = parent, fork rate 10, idle CPU, no delay unless the "
              "table says otherwise.\n")
    if invalid:
        md.append(f"**{len(invalid)} INVALID run(s) excluded** (strategy could not be applied): "
                  + ", ".join(f"{p}:{rid}" for p, rid in invalid) + "\n")

    if A:
        md.append("## A. Baseline: every attack against every strategy (H1, H2, H3)\n")
        md.append(table(["technique"] + STRATS,
                        [[t] + [erad(pick(A, technique=t, strategy=s)) for s in STRATS] for t in TECHS]))
        md.append("\nMean time to clear (ms, successful runs only):\n\n")
        md.append(table(["technique"] + STRATS,
                        [[t] + [fmt(mean(r["time_to_clear_ms"] for r in pick(A, technique=t, strategy=s)
                                         if r["eradicated"] == "1")) for s in STRATS] for t in TECHS]))
        md.append("\nMean attack processes still alive at the end (survivors_at_end):\n\n")
        md.append(table(["technique"] + STRATS,
                        [[t] + [fmt(mean(r["survivors_at_end"] for r in pick(A, technique=t, strategy=s)), digits=1)
                                for s in STRATS] for t in TECHS]))
        md.append("\nOverall eradication rate per strategy (all four attacks):\n\n")
        md.append(table(["strategy", "eradicated", "rate"],
                        [[s, erad(pick(A, strategy=s)), fmt((erad_rate(pick(A, strategy=s)) or 0) * 100, "%")]
                         for s in STRATS if pick(A, strategy=s)]))

    if B:
        md.append("\n## B. Fork rate (H1)\n")
        rates = sorted({int(r["fork_rate"]) for r in B} | {10})
        for t in TECHS:
            strats = [s for s in STRATS if pick(B, technique=t, strategy=s)]
            if not strats:
                continue
            md.append(f"\n**{t}**: eradicated/total (mean survivors at end)\n\n")
            rows = []
            for s in strats:
                cells = []
                for f in rates:
                    src = A if f == 10 else B
                    rr = pick(src, technique=t, strategy=s, fork_rate=f)
                    cells.append(f"{erad(rr)} ({fmt(mean(r['survivors_at_end'] for r in rr), digits=1)})" if rr else "-")
                rows.append([s] + cells)
            md.append(table(["strategy"] + [f"{f}/s" for f in rates], rows))

    if C:
        md.append("\n## C. CPU contention (scheduling)\n")
        md.append("\nEradicated/total, then mean time to clear in ms for successful runs.\n\n")
        rows = []
        for t in TECHS:
            for s in STRATS:
                if not pick(C, technique=t, strategy=s):
                    continue
                cells = []
                for load in ["idle", "medium", "high"]:
                    src = A if load == "idle" else C
                    rr = pick(src, technique=t, strategy=s, cpu_load=load)
                    cells.append(f"{erad(rr)}, {fmt(mean(r['time_to_clear_ms'] for r in rr if r['eradicated'] == '1'), ' ms')}" if rr else "-")
                rows.append([t, s] + cells)
        md.append(table(["technique", "strategy", "idle", "medium", "high"], rows))

    if D:
        md.append("\n## D. Inference delay (H4)\n")
        levels = delay_levels(D)
        md.append("\nEradicated/total; then processes alive when the kill landed -> still alive at the end (means).\n\n")
        rows = []
        for t in TECHS:
            for s in STRATS:
                if not pick(D, technique=t, strategy=s):
                    continue
                cells = []
                for label, d, m in levels:
                    rr = pick(A, technique=t, strategy=s) if d == "0" else pick(D, technique=t, strategy=s, delay_ms=d)
                    cells.append(f"{erad(rr)}; {fmt(mean(r['alive_at_kill'] for r in rr))} -> "
                                 f"{fmt(mean(r['survivors_at_end'] for r in rr))}" if rr else "-")
                rows.append([t, s] + cells)
        md.append(table(["technique", "strategy"] + [l for l, _, _ in levels], rows))

    if E:
        md.append("\n## E. Collateral damage (H5)\n")
        md.append("\nBenign processes killed / benign processes started, summed over all runs.\n\n")
        rows = []
        for t in TECHS:
            for s in STRATS:
                rs = pick(E, technique=t, strategy=s)
                if not rs:
                    continue
                ra = pick(A, technique=t, strategy=s)
                kill = lambda rr: f"{sum(int(r['benign_killed']) for r in rr)}/{sum(int(r['benign_total']) for r in rr)}" if rr else "-"
                rows.append([t, s, kill(ra), kill(rs), erad(rs)])
        md.append(table(["technique", "strategy", "benign separate (A)", "benign shared (E)", "eradicated (E)"], rows))

    if F:
        md.append("\n## F. Which PID the detector flags (sensitivity)\n")
        rows = []
        for t in TECHS:
            for s in STRATS:
                rf = pick(F, technique=t, strategy=s)
                if rf:
                    rows.append([t, s, erad(pick(A, technique=t, strategy=s)), erad(rf)])
        md.append(table(["technique", "strategy", "target = parent (A)", "target = newest (F)"], rows))
    return "\n".join(md)


# ---------------------------------------------------------------- figures
def style(ax, title=None):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    if title:
        ax.set_title(title, color=INK, fontsize=11, loc="left")


def make_figures(data, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import LinearSegmentedColormap
    except ImportError:
        print("matplotlib not installed -- tables written, figures skipped "
              "(activate your venv: source ~/ai-agent-env/bin/activate)")
        return []
    os.makedirs(outdir, exist_ok=True)
    made = []
    A, B, C, D, E = (data[k] for k in "ABCDE")
    plt.rcParams.update({"font.family": "DejaVu Sans", "figure.facecolor": SURFACE})

    # 1. baseline heatmap ------------------------------------------------
    if A:
        strats = [s for s in STRATS if pick(A, strategy=s)]
        grid = [[erad_rate(pick(A, technique=t, strategy=s)) for s in strats] for t in TECHS]
        cmap = LinearSegmentedColormap.from_list("seq", [SEQ_BLUE[0], SEQ_BLUE[-1]])
        fig, ax = plt.subplots(figsize=(9, 3.6))
        vals = [[v if v is not None else float("nan") for v in row] for row in grid]
        ax.imshow(vals, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(strats)), strats)
        ax.set_yticks(range(len(TECHS)), TECHS)
        for i, t in enumerate(TECHS):
            for j, s in enumerate(strats):
                rr = pick(A, technique=t, strategy=s)
                if rr:
                    v = erad_rate(rr)
                    ax.text(j, i, erad(rr), ha="center", va="center", fontsize=10,
                            color="white" if v > 0.55 else INK)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_xticks([x - 0.5 for x in range(1, len(strats))], minor=True)
        ax.set_yticks([y - 0.5 for y in range(1, len(TECHS))], minor=True)
        ax.grid(which="minor", color=SURFACE, linewidth=2)
        ax.tick_params(which="both", length=0, colors=INK2)
        ax.set_title("Eradication rate by attack and termination strategy (runs eradicated / runs)",
                     color=INK, fontsize=11, loc="left")
        fig.tight_layout()
        p = os.path.join(outdir, "fig1_baseline_heatmap.png"); fig.savefig(p, dpi=200); plt.close(fig); made.append(p)

    # 2. fork rate: one panel per technique ----------------------------
    if B:
        techs = [t for t in TECHS if pick(B, technique=t)]
        rates = sorted({int(r["fork_rate"]) for r in B} | {10})
        fig, axes = plt.subplots(1, len(techs), figsize=(4 * len(techs), 3.4), sharey=True, squeeze=False)
        for ax, t in zip(axes[0], techs):
            ss = [s for s in STRATS if pick(B, technique=t, strategy=s)]
            for k, s in enumerate(ss):
                ys = [erad_rate(pick(A if f == 10 else B, technique=t, strategy=s, fork_rate=f)) for f in rates]
                ax.plot(range(len(rates)), [y + dodge(k, len(ss), 1) if y is not None else float("nan") for y in ys],
                        color=STRAT_COLOR[s], linewidth=2, marker=STRAT_MARKER[s], markersize=8,
                        markeredgecolor=SURFACE, markeredgewidth=2, label=s)
            ax.set_xticks(range(len(rates)), [f"{f}/s" for f in rates])
            ax.set_ylim(-0.1, 1.1)
            style(ax, t)
        axes[0][0].set_ylabel("eradication rate", color=INK2)
        fig.text(0.01, -0.02, "Lines are offset slightly so strategies with identical results stay visible.",
                 color=INK2, fontsize=8)
        axes[0][-1].legend(frameon=False, fontsize=9, loc="center left", bbox_to_anchor=(1, 0.5))
        fig.suptitle("Eradication rate vs attacker fork rate", color=INK, fontsize=12, x=0.01, ha="left")
        fig.tight_layout()
        p = os.path.join(outdir, "fig2_fork_rate.png"); fig.savefig(p, dpi=200, bbox_inches="tight"); plt.close(fig); made.append(p)

    # 3. CPU load: mean time to clear, grouped bars ----------------------
    if C:
        strats = [s for s in STRATS if pick(C, strategy=s)]
        loads = ["idle", "medium", "high"]
        shades = [SEQ_BLUE[1], SEQ_BLUE[3], SEQ_BLUE[5]]   # ordinal: light -> dark
        fig, axes = plt.subplots(1, len(TECHS), figsize=(4 * len(TECHS), 3.4), sharey=True, squeeze=False)
        w = 0.26
        for ax, t in zip(axes[0], TECHS):
            any_cleared = False
            for k, load in enumerate(loads):
                ys = []
                for s in strats:
                    rr = pick(A if load == "idle" else C, technique=t, strategy=s, cpu_load=load)
                    v = mean(r["time_to_clear_ms"] for r in rr if r["eradicated"] == "1")
                    any_cleared = any_cleared or v is not None
                    ys.append(v or 0)
                ax.bar([i + (k - 1) * (w + 0.02) for i in range(len(strats))], ys, width=w,
                       color=shades[k], label=f"{load} CPU", edgecolor=SURFACE, linewidth=1)
            ax.set_xticks(range(len(strats)), strats)
            if not any_cleared:
                ax.text(0.5, 0.5, "never fully cleared\nby these strategies", transform=ax.transAxes,
                        ha="center", va="center", color=INK2, fontsize=10)
            style(ax, t)
        axes[0][0].set_ylabel("mean time to clear (ms)", color=INK2)
        axes[0][-1].legend(frameon=False, fontsize=9, loc="center left", bbox_to_anchor=(1, 0.5))
        fig.suptitle("Time from kill to full eradication under CPU contention (successful runs; 0 = never cleared)",
                     color=INK, fontsize=12, x=0.01, ha="left")
        fig.tight_layout()
        p = os.path.join(outdir, "fig3_cpu_load.png"); fig.savefig(p, dpi=200, bbox_inches="tight"); plt.close(fig); made.append(p)

    # 4. delay: share of attack removed ----------------------------------
    if D:
        levels = delay_levels(D)
        techs = [t for t in TECHS if pick(D, technique=t)]
        fig, axes = plt.subplots(1, len(techs), figsize=(5.5 * len(techs), 3.6), sharey=True, squeeze=False)
        for ax, t in zip(axes[0], techs):
            ss = [s for s in STRATS if pick(D, technique=t, strategy=s)]
            for k, s in enumerate(ss):
                ys = []
                for label, d, m in levels:
                    rr = pick(A, technique=t, strategy=s) if d == "0" else pick(D, technique=t, strategy=s, delay_ms=d)
                    v = removed_share(rr)
                    ys.append(float("nan") if v is None else v * 100 + dodge(k, len(ss), 100))
                ax.plot(range(len(levels)), ys, color=STRAT_COLOR[s], linewidth=2, marker=STRAT_MARKER[s], markersize=8,
                        markeredgecolor=SURFACE, markeredgewidth=2, label=s)
            ax.set_xticks(range(len(levels)), [l for l, _, _ in levels], fontsize=8)
            ax.set_ylim(-10, 110)
            style(ax, t)
        axes[0][0].set_ylabel("% of attack processes removed", color=INK2)
        fig.text(0.01, -0.03, "Lines are offset slightly so strategies with identical results stay visible. "
                 "Removed = 1 - survivors at end / (alive at kill + respawns).", color=INK2, fontsize=8)
        axes[0][-1].legend(frameon=False, fontsize=9, loc="center left", bbox_to_anchor=(1, 0.5))
        fig.suptitle("How much of the attack each strategy removes as the defender's inference delay grows",
                     color=INK, fontsize=12, x=0.01, ha="left")
        fig.tight_layout()
        p = os.path.join(outdir, "fig4_delay.png"); fig.savefig(p, dpi=200, bbox_inches="tight"); plt.close(fig); made.append(p)

    # 5. benign harm -----------------------------------------------------
    if E:
        strats = [s for s in STRATS if pick(E, strategy=s)]
        def frac(rr):
            tot = sum(int(r["benign_total"]) for r in rr)
            return 100 * sum(int(r["benign_killed"]) for r in rr) / tot if tot else 0
        sep = [frac(pick(A, strategy=s)) for s in strats]
        shr = [frac(pick(E, strategy=s)) for s in strats]
        fig, ax = plt.subplots(figsize=(7, 3.4))
        w = 0.36
        ax.bar([i - w / 2 - 0.01 for i in range(len(strats))], sep, width=w, color=SERIES[0], label="benign separate from attacker")
        ax.bar([i + w / 2 + 0.01 for i in range(len(strats))], shr, width=w, color=SERIES[1], label="benign shares attacker's group")
        for i, (a, b) in enumerate(zip(sep, shr)):
            ax.text(i - w / 2 - 0.01, a + 2, f"{a:.0f}%", ha="center", fontsize=8, color=INK2)
            ax.text(i + w / 2 + 0.01, b + 2, f"{b:.0f}%", ha="center", fontsize=8, color=INK2)
        ax.set_xticks(range(len(strats)), strats)
        ax.set_ylim(0, 110)
        ax.set_ylabel("% of benign processes killed", color=INK2)
        style(ax, "Collateral damage: innocent processes killed by each strategy")
        ax.legend(frameon=False, fontsize=9, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2)
        fig.tight_layout()
        p = os.path.join(outdir, "fig5_benign_harm.png"); fig.savefig(p, dpi=200, bbox_inches="tight"); plt.close(fig); made.append(p)
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", default="results")
    args = ap.parse_args()
    if not os.path.isdir(args.results_dir):
        sys.exit(f"no results directory '{args.results_dir}' -- run run_matrix.sh first")
    data, invalid = load(args.results_dir)
    if not any(data.values()):
        sys.exit(f"no valid rows in {args.results_dir}/")
    md = build_markdown(data, invalid)
    out = os.path.join(args.results_dir, "summary.md")
    open(out, "w").write(md)
    print(f"wrote {out}")
    for p in make_figures(data, os.path.join(args.results_dir, "figures")):
        print(f"wrote {p}")
    if invalid:
        print(f"WARNING: {len(invalid)} invalid run(s) excluded -- see the top of summary.md")


if __name__ == "__main__":
    main()
