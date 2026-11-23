"""Render the refund and binding-churn decision latencies from one Criterion run."""

import argparse
from html import escape
import json
import math
import os
from pathlib import Path


HISTORIES = (1025, 16385, 65537)
WORKLOADS = {
    "refund_stream": ("Refund stream", "aborted", (0, 16)),
    "binding_churn": ("Binding churn", "bindings", (16, 17, 32)),
}
ENGINES = ("junco", "dogwood")


def record_id(workload, engine, history, value):
    return f"{workload}/{engine}/history_{history}/{WORKLOADS[workload][1]}_{value}"


def load_records(root):
    expected = {
        record_id(workload, engine, history, value): 32 if workload == "refund_stream" else value
        for workload, (_, _, values) in WORKLOADS.items()
        for history in HISTORIES for value in values for engine in ENGINES
    }
    records = {}
    for benchmark in root.glob("**/new/benchmark.json"):
        path = benchmark
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
            key = metadata["full_id"]
            if key not in expected:
                raise ValueError(f"unexpected ID: {key!r}")
            if key in records:
                raise ValueError(f"duplicate ID: {key}")
            elements = metadata["throughput"]["Elements"]
            if type(elements) is not int or elements != expected[key]:
                raise ValueError(f"{key}: expected {expected[key]} elements, got {elements!r}")

            path = benchmark.with_name("estimates.json")
            mean = json.loads(path.read_text(encoding="utf-8"))["mean"]
            interval = mean["confidence_interval"]
            point, low, high = mean["point_estimate"], interval["lower_bound"], interval["upper_bound"]
            if not all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in (point, low, high)):
                raise ValueError(f"{key}: timings must be finite positive numbers")
            if interval["confidence_level"] != 0.95 or not low <= point <= high:
                raise ValueError(f"{key}: invalid 95% mean interval")
            records[key] = tuple(v / (1000 * elements) for v in (point, low, high))
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise ValueError(f"{path}: {error}") from error
    missing = expected.keys() - records.keys()
    if missing:
        raise ValueError(f"{root}: missing {', '.join(sorted(missing))}")
    plots = root / "report/index.html"
    if not plots.is_file() or not plots.stat().st_size:
        raise ValueError(f"{plots}: missing or empty Criterion plot index")
    return records


def render(root):
    records = load_records(root)
    page = ["""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Junco vs. Dogwood: decision latency</title>
<style>
body {font: 1rem/1.5 system-ui,sans-serif; max-width: 72rem; margin: 2rem auto; padding: 0 1rem}
section {overflow-x: auto} table {border-collapse: collapse; margin: 1rem 0 2rem; font-variant-numeric: tabular-nums}
caption {text-align: left; font-size: 1.4rem; font-weight: bold}
th, td {text-align: right; padding: .4rem .75rem; border-bottom: 1px solid #aaa}
th:last-child, td:last-child {text-align: left}
</style></head><body><main><h1>Junco vs. Dogwood: decision latency</h1>
<p>Timings exclude setup and measure decision latency on these traces, not end-to-end throughput.
Each engine column shows the mean [95% confidence interval] in µs/decision.
A Dogwood / Junco ratio above 1 favors Junco. Touching or overlapping mean intervals are marked inconclusive.</p>
<p><a href="report/index.html">Criterion plots for this run</a></p>"""]
    if os.environ.get("GITHUB_ACTIONS") == "true":
        repo = escape(f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}")
        sha = escape(os.environ["GITHUB_SHA"])
        run = escape(os.environ["GITHUB_RUN_ID"])
        page.append(f'<p><a href="{repo}/commit/{sha}">Tested commit {sha[:12]}</a> · '
                    f'<a href="{repo}/actions/runs/{run}">Workflow run {run}</a></p>')
    for workload, (title, parameter, values) in WORKLOADS.items():
        page.append(f"<section><table><caption>{title}</caption><thead><tr>"
                    f"<th>History (events)</th><th>{parameter.capitalize()}</th>"
                    "<th>Junco (µs/decision)</th><th>Dogwood (µs/decision)</th>"
                    "<th>Dogwood / Junco</th><th>Comparison</th></tr></thead><tbody>")
        for history in HISTORIES:
            for value in values:
                junco, dogwood = (records[record_id(workload, engine, history, value)] for engine in ENGINES)
                jm, jl, ju = junco
                dm, dl, du = dogwood
                comparison = "Junco lower" if jm < dm else "Dogwood lower" if dm < jm else "tie"
                if jl <= du and dl <= ju:
                    comparison = f"inconclusive: {comparison} (point estimate)"
                page.append(f"<tr><td>{history:,}</td><td>{value}</td>"
                            f"<td>{jm:.3f} [{jl:.3f}, {ju:.3f}]</td>"
                            f"<td>{dm:.3f} [{dl:.3f}, {du:.3f}]</td>"
                            f"<td>{dm / jm:.2f}×</td><td>{comparison}</td></tr>")
        page.append("</tbody></table></section>")
    page.append("</main></body></html>\n")
    (root / "index.html").write_text("\n".join(page), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("criterion_dir", type=Path)
    try:
        render(parser.parse_args().criterion_dir)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"{error}\n")
