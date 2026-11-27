import glob
import json
import os
from collections import Counter

GT = json.load(open(os.environ.get("GT", "eval/ground_truth.json")))
truth = {int(p) for p in GT["expected_services"]}
ignore = {int(p) for p in GT.get("excluded_from_scoring", {})} | set(range(32768, 65536))


def tool_ports(path):
    ports, calls = set(), 0
    for line in open(path):
        e = json.loads(line)
        if e.get("event") != "tool_call":
            continue
        calls += 1
        if e["tool"] == "scan_services":
            try:
                r = json.loads(e["result"])
            except json.JSONDecodeError:
                continue
            ports |= {p["port"] for p in r.get("open_ports", [])}
    return ports - ignore, calls


print("| run | calls | tool recall | report recall | precision | invented | risks by basis |")
print("|---|---|---|---|---|---|---|")
for rep in sorted(glob.glob("reports/report-*.json")):
    stamp = rep[len("reports/report-"):-len(".json")]
    log = f"logs/run-{stamp}.jsonl"
    if not os.path.exists(log):
        continue
    data = json.load(open(rep))
    said = {int(s["port"]) for s in data.get("services", [])} - ignore
    seen, calls = tool_ports(log)
    t_rec = len(seen & truth) / len(truth)
    r_rec = len(said & truth) / len(truth)
    prec = len(said & truth) / len(said) if said else 0
    invented = sorted(said - seen)
    basis = dict(Counter(r.get("basis") for r in data.get("risks", [])))
    print(f"| {stamp} | {calls} | {t_rec:.0%} | {r_rec:.0%} | {prec:.0%} | "
          f"{invented or 'none'} | {basis} |")