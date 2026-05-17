# Documentation Conventions

## General Guidelines

- Audience: internal developers and AI agents.
- Tone: direct and concise. Lead with the what and how.
- Use present tense and active voice.
- One topic per file.
- File naming: `UPPER-CASE.md` for all documentation files, with hyphens to separate words. Documents inside initiative directories are prefixed with their type (`TRD-`, `RFC-`, `TASK-`) and are not date-prefixed.
- Links between docs use relative paths from the project root.
- Diagrams must use mermaid syntax whenever possible, following the brand theme in `docs/conventions/MERMAID-THEME.md`.
- Documentation must be updated when the code it describes changes.

## Organization

```
docs/
├── architecture/              # System design and architecture docs
├── conventions/               # Code conventions, patterns, tool preferences
├── sops/                      # Standard Operating Procedures — step-by-step process guides
├── features/                  # Initiative directories
│   └── YYYY-MM-DD-initiative-name/
│       ├── TRD-INITIATIVE-NAME.md
│       ├── RFC-PROPOSAL-NAME.md
│       └── TASK-WORK-ITEM.md
└── tools/                     # Tool usage (if needed)
```

### Initiative Directories

All TRDs, RFCs, and Tasks are stored in initiative directories under `docs/features/`. Each initiative directory groups related documents into a single implementation path.

- **Directory naming**: `YYYY-MM-DD-kebab-case-name/` — date-prefixed with the initiative creation date.
- **Document naming**: Files within an initiative directory are prefixed with their type (`TRD-`, `RFC-`, `TASK-`) and use `UPPER-CASE.md`.
- **Every document lives in an initiative directory** — no loose files under `docs/features/`.

## Document Types

### TRD (Technical Requirements Document)

Defines the technical approach for an initiative. Expected to decompose into RFCs.

```markdown
---
Name: [Short name for the initiative]
Summary: [A few sentences describing the initiative and its purpose. Must be a single line.]
Keywords: [Up to 10 comma-separated terms for discoverability. Must be a single line.]
---

# [Initiative Name]

## Technical Motivation
## Goals
## Requirements
### Functional
### Non-Functional
## Scope
### In Scope
### Out of Scope
## Architecture
## Success Criteria
## Open Questions
```

### RFC (Request for Change)

A focused plan for a single change, written for the engineer who will implement it.

```markdown
---
Name: [Short name for the change]
Summary: [1-2 sentences describing the change. Must be a single line.]
Keywords: [5-10 comma-separated terms for discoverability. Must be a single line.]
Source: [Relative path to the parent TRD]
Dependencies: [Comma-separated relative paths to sibling RFCs this depends on. Omit if none.]
---

# [Title]

## Context
## Change
## Affected Areas
## Alternatives Considered
```

### Task

A discrete work item decomposed from an RFC. Tasks are ephemeral.

```markdown
---
Name: [Short name for the task]
Summary: [What this task accomplishes. Must be a single line.]
Source: [Relative path to the RFC this task was decomposed from]
Dependencies: [Comma-separated relative paths to TASK files this depends on. Omit if none.]
---

# [Task Name]

## Objective
## Acceptance Criteria
## Notes
```

### Convention

Standards, patterns, and rules the team follows. Stored in `docs/conventions/`. Formatting may vary.

### SOP (Standard Operating Procedure)

Step-by-step process guides. Stored in `docs/sops/`.

```markdown
# [Process Name]

## Purpose
## Prerequisites
## Steps
```
