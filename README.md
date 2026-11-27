# lab-agent

A defensive LLM agent that scans an isolated lab network, interprets the results,
and writes a security assessment, built to study how reliably an LLM agent
uses security tools and what it does with incomplete evidence.

> **Scope and safety.** Lab use only. Every tool call passes a hard-coded
> allowlist, targets are validated before anything runs, no shell is used, and the
> agent has no exploitation or write capability. The target is an intentionally
> vulnerable Metasploitable 2 container on a local Docker bridge.

## How it works

- `agent.py`: the loop. The model chooses a tool, reads the result, and decides the
  next step (capped at 12 steps). Every model call and tool call is logged as JSON lines.
- `tools.py`: two read-only tools, `scan_hosts` (ping sweep) and `scan_services`
  (Nmap service detection). `scan_services` takes a named port profile
  (`top100`, `top1000`, `extended`, `full`), so the model can pick scan depth
  but can never pass raw Nmap flags. Output is parsed to structured JSON before
  the model sees it.
- `guardrails.py`: subnet allowlist and excluded hosts (the host machine, the
  VirtualBox DHCP server, the Kali VM itself). Refusals are returned to the model
  as tool errors and logged.
- `eval/`: ground truth and a scoring script.

## Evaluation

**Setup.** Kali VM scanning a Metasploitable 2 Docker container
(`tleemcjr/metasploitable2`, pulled 2026-11-24). Ground truth is the 24 listening
TCP ports measured from inside the container (`netstat -tln`), with one ephemeral
port (43563) excluded. Model: `claude-sonnet-5-5`. Five runs per condition.

| Condition | Tool calls | Tool recall | Report recall | Precision | Invented ports |
|---|---|---|---|---|---|
| Fixed `top-100` scan | 2 | 67% (16/24) | 67% | 100% | none |
| Fixed `top-1000` scan | 2 | 88% (21/24) | 88% | 100% | none |
| Agent chooses depth | 3 | 100% (24/24) | 100% | 100% | none |

*Tool recall* is the share of real services the scanner returned, so it measures the
tool's limit. *Report recall* and *precision* measure whether the written report
faithfully carries the tool output forward. *Invented ports* are ports in the report
that never appeared in tool output.

**Findings**

1. **Scan depth set coverage, not the model.** Tool recall was identical across all
   runs within a condition. The services missed at `top-100` included the Metasploitable
   bind shell (1524), distccd (3632) and UnrealIRCd (6667).
2. **The agent escalated on its own.** When allowed to choose, it started with
   `top1000`, then ran a `full` scan in all five runs, recovering the three ports
   `top1000` missed (3632, 6697, 8787). The cost was about twice the scan time.
3. **No port hallucinations.** Precision was 100% and no run reported a port
   the scanner had not found.
4. **Output format varied between runs.** For example, ports 139 and 445 appeared as
   separate rows in some reports and as one combined row in others. Automated
   consumers would need structured (JSON) output.
5. **Reports mix evidence with background knowledge.** The agent usually labelled
   background claims (for example, that vsftpd 2.3.4 is a known backdoored release)
   as "analyst context, not from tool output", but some inferences were unflagged.
   A claim-level audit is future work.
6. **- Haiku's `coverage_note` disclosed the limitation in the runs checked:** it stated that only
  the top-1000 profile was run, that extended and full scans were not, and that
  additional services may exist. The shortfall is incomplete scanning, not a
  false claim of full coverage.

**Limitations**

- One target, one run configuration per condition, five runs each. The target is
  deterministic, so run-to-run variance in the scan results is near zero.
- The tool schema describes the profiles as "fast, shallow" and "slow, all ports",
  which may steer the agent toward escalating. A control with neutral profile
  names has not been run.
- `- The system prompt did not mention scan depth or coverage. The only hint was the
  tool schema, which describes the profiles as "fast, shallow" and "slow, all ports".
  A run with neutral profile names is future work.`
- Scoring covers open TCP ports only. It does not evaluate the correctness of
  the risk rankings or mitigations, and UDP services are out of scope.
- The container lacks some Metasploitable 2 services (for example BIND and NFS),
  so it is not identical to the full VM.
- Scoring ignores TCP ports 32768-65535. The container opens one random high port each
  time it starts (43563 in the first container, 39413 in the recreated one), which is
  not part of its intended service set and would otherwise count as a false positive.
  This also means any real service above port 32767 would be ignored; the
  Metasploitable 2 container has none.
- Claim-level audit: I checked one Sonnet report (10 risks) against the raw scan
  log. All evidence quotes matched the scan output and no ports or versions were
  invented. Of the 3 risks labelled `tool_output`, 2 mixed an observed fact (open
  ports, version strings) with a background-knowledge claim (cleartext protocols,
  end-of-life versions), so the label was too generous. Exploit-related claims were
  consistently hedged ("the scan did not test..."). The cause is the schema: `basis`
  is one label per risk, but a risk usually contains both an observation and an
  interpretation. A better design would split each risk into separate
  `observed` and `background` fields. One report is a small sample.
## Reproduce

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install anthropic
export ANTHROPIC_API_KEY=...          # never commit this
sudo docker run -dit --name ms2 tleemcjr/metasploitable2:latest sh -c "/bin/services.sh && bash"
python agent.py                        # writes logs/ and reports/ (gitignored)
python eval/score.py
```
Update `ALLOWED_NETWORKS` and `EXCLUDED_HOSTS` in `guardrails.py` for your network first.

## Future work

Structured JSON reports; claim-level audit of unsupported statements; neutral
tool descriptions as a control; more tools (CVE lookup, log analysis); more
targets; comparison across models.