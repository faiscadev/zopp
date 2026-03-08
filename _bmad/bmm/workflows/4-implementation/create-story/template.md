# Story {{epic_num}}.{{story_num}}: {{story_title}}

Status: ready-for-dev

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a {{role}},
I want {{action}},
so that {{benefit}}.

## Acceptance Criteria

1. [Add acceptance criteria from epics/PRD]

## Tasks / Subtasks

- [ ] Task 1 (AC: #)
  - [ ] Subtask 1.1
- [ ] Task 2 (AC: #)
  - [ ] Subtask 2.1

## Dev Notes

- Relevant architecture patterns and constraints
- Source tree components to touch
- Testing standards summary

### Project Structure Notes

- Alignment with unified project structure (paths, modules, naming)
- Detected conflicts or variances (with rationale)

### References

- Cite all technical details with source paths and sections, e.g. [Source: docs/<file>.md#Section]

### Pre-Submission Checklist

Before submitting a PR, verify each item relevant to your story's scope.

**Security** (if story touches gRPC endpoints, auth, or user-supplied content):

- [ ] Input validation on all user-facing fields (length, format, required)
- [ ] TOCTOU race conditions prevented (use DB constraints, not check-then-act)
- [ ] No secrets or plaintext keys leaked in logs or error messages
- [ ] No user enumeration via error messages (use generic responses for auth failures)
- [ ] Zeroizing types used for sensitive data (`zeroize::Zeroize`, `ZeroizeOnDrop`)
- [ ] Authorization ownership validated for resource IDs in request parameters

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
