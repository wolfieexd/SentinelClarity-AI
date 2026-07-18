# 60-Second Judge Demo Script

Use this walkthrough for Devpost, live judging, or a short screen recording.

## Setup

```bash
git clone https://github.com/wolfieexd/SentinelClarity-AI.git
cd SentinelClarity-AI
./scripts/judge-demo.sh
```

## Narration

1. **Open with the problem.** Smart contract teams need security feedback before vulnerable Clarity code reaches mainnet.
2. **Show the target.** Open `sentinel-test-corpus/contracts/demo/vulnerable-dao.clar`, which intentionally contains missing access control, unchecked arithmetic, external-call ordering risk, unchecked responses, and read-only mutation.
3. **Run the scanner.** Execute the demo script or the manual scan command:

   ```bash
   cargo run --package sentinel-cli -- scan sentinel-test-corpus/contracts/demo/vulnerable-dao.clar --format markdown --triage --fail-on critical
   ```

4. **Explain the output.** Point to the finding table, then explain that each finding is normalized for SARIF, markdown, JSON, and AI triage.
5. **Show AI-native triage.** Highlight exploitability, blast radius, root cause, confidence, and fix strategy in `artifacts/demo-output.md`.
6. **Show developer workflow.** Open `artifacts/fix-plan.md` to show the PR-ready remediation plan.
7. **Close with the roadmap.** The current MVP is deterministic and CI-safe; the next step is live OpenAI triage and automated PRs behind the existing interfaces.

## Suggested Closing Line

“SentinelClarity turns Clarity contract review into a continuous, explainable developer workflow: static analysis finds the risk, AI triage explains it, and Codex-style fix packages make remediation reviewable.”
