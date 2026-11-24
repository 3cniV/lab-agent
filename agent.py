import json
import os
from datetime import datetime

import anthropic
from tools import TOOL_SCHEMAS, run_tool

MODEL = "claude-sonnet-5-5"   # try "claude-haiku-5-5" later and compare
MAX_STEPS = 12
MAX_RESULT_CHARS = 8000

SYSTEM = """You are a defensive network security analyst working in an isolated lab.
Scope: only the lab networks 192.168.56.0/24 and 172.17.0.0/24. Tools refuse anything else.
Use the tools to discover hosts and identify services, then write a findings report.
Rules: only report what the tool output supports; if something is unknown, say "unknown".
Do not invent CVEs or versions. Report format: 1) hosts found, 2) services per host,
3) risks ranked by severity with the evidence for each, 4) recommended defensive mitigations."""

GOAL = "Assess the security posture of the lab network 172.17.0.0/24 and write a report."

client = anthropic.Anthropic()


def main():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log = open(f"logs/run-{stamp}.jsonl", "w")

    def record(event):
        log.write(json.dumps(event) + "\n")
        log.flush()

    record({"event": "start", "model": MODEL, "goal": GOAL})
    messages = [{"role": "user", "content": GOAL}]
    final_text = ""

    for step in range(MAX_STEPS):
        resp = client.messages.create(
            model=MODEL, max_tokens=2000, system=SYSTEM,
            tools=TOOL_SCHEMAS, messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})

        calls = [b for b in resp.content if b.type == "tool_use"]
        if not calls:
            final_text = "".join(b.text for b in resp.content if b.type == "text")
            record({"event": "final", "step": step})
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

    path = f"reports/report-{stamp}.md"
    with open(path, "w") as f:
        f.write(final_text or "(no final report produced)")
    print(final_text or "(no final report produced)")
    print(f"\nLog: logs/run-{stamp}.jsonl | Report: {path}")


if __name__ == "__main__":
    main()