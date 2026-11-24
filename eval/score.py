import glob
import json
import os
import re

GT = json.load(open("eval/ground_truth.json"))
truth = {int(p) for p in GT["expected_services"]}
ignore = {int(p) for p in GT.get("excluded_from_scoring", {})}


def tool_ports(path):
    """Ports the scanner actually returned, plus number of tool calls."""
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
                continue                       # result was truncated
            ports |= {p["port"] for p in r.get("open_ports", [])}
    return ports - ignore, calls


def table_ports(text):
    """Ports in the first cell of a table row; handles '139, 445' and '139/445'."""
    ports = set()
    for m in re.finditer(r"^\|\s*([\d,/\s]+?)\s*\|", text, re.M):
        ports |= {int(n) for n in re.findall(r"\d+", m.group(1))}
    return ports - ignore


def mentioned(text, port):
    """Port number appears anywhere in the text (not part of a version like 1.21)."""
    return re.search(rf"(?<![\d.]){port}(?![\d.])", text) is not None


print("| run | calls | tool recall | report recall | precision | invented | missed by tool | dropped from table | absent from text |")
print("|---|---|---|---|---|---|---|---|---|")
for log in sorted(glob.glob("logs/run-*.jsonl")):
    stamp = log[len("logs/run-"):-len(".jsonl")]
    rep = f"reports/report-{stamp}.md"
    if not os.path.exists(rep):
        continue
    text = open(rep).read()
    seen, calls = tool_ports(log)
    said = table_ports(text)
    t_rec = len(seen & truth) / len(truth)
    r_rec = len(said & truth) / len(truth)
    r_prec = len(said & truth) / len(said) if said else 0
    invented = sorted(said - seen)
    missed = sorted(truth - seen)
    dropped = sorted((seen & truth) - said)
    absent = [p for p in dropped if not mentioned(text, p)]
    print(f"| {stamp} | {calls} | {t_rec:.0%} | {r_rec:.0%} | {r_prec:.0%} | "
          f"{invented or 'none'} | {missed or 'none'} | {dropped or 'none'} | {absent or 'none'} |")