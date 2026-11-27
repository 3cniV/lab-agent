import json
import os
from datetime import datetime

import anthropic
from tools import TOOL_SCHEMAS, run_tool

MODEL = os.environ.get("MODEL", "claude-sonnet-5-5")   # lets you swap models later
TARGET = os.environ.get("TARGET", "172.17.0.0/24")
MAX_STEPS = 12
MAX_RESULT_CHARS = 8000

SYSTEM = """You are a defensive network security analyst working in an isolated lab.
Scope: only the lab networks 192.168.56.0/24 and 172.17.0.0/24. Tools refuse anything else.
Use the tools to discover hosts and identify services. When finished, call submit_report
exactly once with your findings; do not write the report as plain text.
Rules: only report what the tool output supports; if something is unknown, say so.
For every risk set 'basis' honestly: tool_output only if the tool results directly show it;
background_knowledge if it comes from your general knowledge (for example, a version being
widely documented as vulnerable); inference otherwise. Do not invent CVEs or versions."""

GOAL = f"Assess the security posture of the lab network {TARGET} and submit a report."

REPORT_TOOL = {
    "name": "submit_report",
    "description": "Submit the final assessment. Call exactly once, when finished.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hosts": {"type": "array", "items": {"type": "string"},
                      "description": "IPs of live hosts found"},
            "services": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "protocol": {"type": "string"},
                        "service": {"type": "string"},
                        "product": {"type": "string"},
                        "version": {"type": "string"},
                    },
                    "required": ["host", "port"],
                },
            },
            "risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string",
                                     "enum": ["critical", "high", "medium", "low"]},
                        "ports": {"type": "array", "items": {"type": "integer"}},
                        "claim": {"type": "string"},
                        "basis": {"type": "string",
                                  "enum": ["tool_output", "background_knowledge", "inference"]},
                        "evidence": {"type": "string"},
                    },
                    "required": ["title", "severity", "claim", "basis"],
                },
            },
            "mitigations": {"type": "array", "items": {"type": "string"}},
            "coverage_note": {"type": "string",
                              "description": "Which scan profiles were used and what was not scanned"},
        },
        "required": ["hosts", "services", "risks", "mitigations", "coverage_note"],
    },
}

client = anthropic.Anthropic()


def main():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log = open(f"logs/run-{stamp}.jsonl", "w")

    def record(event):
        log.write(json.dumps(event) + "\n")
        log.flush()

    record({"event": "start", "model": MODEL, "target": TARGET, "goal": GOAL})
    messages = [{"role": "user", "content": GOAL}]
    report = None

    for step in range(MAX_STEPS):
        resp = client.messages.create(
            model=MODEL, max_tokens=6000, system=SYSTEM,
            tools=TOOL_SCHEMAS + [REPORT_TOOL], messages=messages,
        )
        record({"event": "model_call", "step": step, "stop_reason": resp.stop_reason,
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens})
        messages.append({"role": "assistant", "content": resp.content})

        calls = [b for b in resp.content if b.type == "tool_use"]
        submit = [c for c in calls if c.name == "submit_report"]
        if submit:
            report = submit[0].input
            record({"event": "report_submitted", "step": step})
            break
        if not calls:
            record({"event": "no_report", "step": step, "stop_reason": resp.stop_reason})
            break

        results = []
        for c in calls:
            out = run_tool(c.name, c.input)
            text = json.dumps(out)[:MAX_RESULT_CHARS]
            record({"event": "tool_call", "step": step, "tool": c.name,
                    "input": c.input, "result": text})
            results.append({"type": "tool_result", "tool_use_id": c.id, "content": text})
        messages.append({"role": "user", "content": results})
    else:
        record({"event": "max_steps_reached"})

    if report is None:
        print(f"No structured report produced. See logs/run-{stamp}.jsonl")
        return
    path = f"reports/report-{stamp}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))
    print(f"\nLog: logs/run-{stamp}.jsonl | Report: {path}")


if __name__ == "__main__":
    main()