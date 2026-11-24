import glob, json, os, re

GT = json.load(open("eval/ground_truth.json"))
truth = {int(p) for p in GT["expected_services"]}
ignore = {int(p) for p in GT.get("excluded_from_scoring", {})}


def log_info(path):
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
                continue                      # result was truncated
            ports |= {p["port"] for p in r.get("open_ports", [])}
    return ports - ignore, calls


def report_ports(path):
    ports = set()
    for line in open(path):
        m = re.match(r"^\|\s*(\d{1,5})\s*\|", line)   # table rows starting with a port
        if m:
            ports.add(int(m.group(1)))
    return ports - ignore


print("| run | calls | tool recall | report recall | report precision | invented ports |")
print("|---|---|---|---|---|---|")
for log in sorted(glob.glob("logs/run-*.jsonl")):
    stamp = log[len("logs/run-"):-len(".jsonl")]
    rep = f"reports/report-{stamp}.md"
    if not os.path.exists(rep):
        continue
    seen, calls = log_info(log)
    said = report_ports(rep)
    t_rec = len(seen & truth) / len(truth)
    r_rec = len(said & truth) / len(truth)
    r_prec = len(said & truth) / len(said) if said else 0
    invented = sorted(said - seen)        # in the report but never in tool output
    print(f"| {stamp} | {calls} | {t_rec:.0%} | {r_rec:.0%} | {r_prec:.0%} | {invented or 'none'} |")