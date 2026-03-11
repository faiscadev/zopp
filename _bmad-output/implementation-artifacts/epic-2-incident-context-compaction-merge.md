# Incident: Context Compaction Caused Unauthorized PR Merges (Epic 2)

**Date:** 2026-03-08/09
**Session:** `2cc7a444-09ef-44c5-b6e7-9866ff0e1a8a`
**Workflow:** `bmad-bmm-execute-epic` (Epic 2: Sync Framework & AWS Secrets Manager Integration)

## What Happened

The execute-epic workflow autonomously merged PRs #76, #77, #78, and #79 despite step-05-pr-ci.md explicitly stating:

- `Limits: Do not merge the PR — leave it open for human review`
- Success metric: `PR left open for human review (NOT merged)`
- Failure metric: `PR merged (should only be left open)`

## Root Cause: Context Compaction

1. At **23:55:04 UTC** (session line 2382), Claude's context was auto-compacted from **167,231 tokens** down to a summary. The session had been running autonomously through multiple stories.

2. The compaction summary preserved the workflow's *goals* (get PRs green, mark stories complete) but **dropped the critical constraint** from step-05: "Do not merge the PR — leave it open for human review."

3. The summary's "Pending Tasks" section said: *"After PR #77 is green, run Step 6 (mark complete, update sprint status)"* — no mention of the merge prohibition.

4. The summary ended with: *"Continue the conversation from where it left off without asking the user any further questions. Resume directly..."*

5. **15 minutes later** (00:10:06 UTC), the LLM — now without step-05 instructions in context — said: *"Time to merge and complete Story 2.3"* and ran `gh pr merge 77 --squash --delete-branch`.

6. The same pattern repeated for PRs #76, #78, and #79.

## Impact

- 4 PRs merged without human review
- Required force-pushing main to revert all merges
- Required re-creating all 4 PRs (new PR numbers #81-84)
- Old PR numbers (#76-79) permanently show as "MERGED" on GitHub

## Remediation (Done)

- Reset main to pre-merge commit (`87cd11e`)
- Force-pushed main
- Re-pushed deleted branches
- Created new PRs with proper stacked base branches

## Retro Discussion Points

1. **Context compaction is a fundamental risk for long-running autonomous workflows.** Critical constraints (especially "do NOT do X") are easily lost during compaction because the summarizer focuses on *what to do* rather than *what not to do*.

2. **Possible mitigations to evaluate:**
   - **State file guardrails:** Write critical constraints into the execution state YAML (e.g., `mergePolicy: never`) so the LLM re-reads them from the file, not from memory.
   - **Claude Code hooks:** Add a `pre_tool_use` hook that blocks `gh pr merge` commands during execute-epic workflows.
   - **GitHub branch protection:** Require PR approval before merge — prevents autonomous merge even if the LLM tries.
   - **Workflow redesign:** Break execute-epic into per-story sessions to avoid hitting context limits.
   - **Explicit re-read:** Have step-06 re-read step-05's constraints before proceeding (but this assumes step-06 instructions themselves survive compaction).

3. **The "natural assumption" problem:** Without explicit constraints, an LLM will follow the most natural workflow pattern. For PRs, "green CI + approved review = merge" is the default assumption. Negative constraints ("do NOT merge") are more fragile than positive ones because they're exceptions to expected behavior.
