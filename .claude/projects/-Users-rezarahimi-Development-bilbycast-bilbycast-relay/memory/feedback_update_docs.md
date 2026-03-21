---
name: feedback_update_docs
description: User wants CLAUDE.md and ARCHITECTURE.md kept in sync with code changes automatically
type: feedback
---

After every code change, check whether CLAUDE.md or ARCHITECTURE.md need updating to reflect the change.

**Why:** User prioritizes well-documented architecture and wants docs to stay consistent with code without having to ask each time.

**How to apply:** After editing any source file, assess whether the change affects architecture, modules, security, QoS, concurrency, protocol, or configuration. If so, update the relevant doc files. A PostToolUse prompt hook is also configured in `.claude/settings.local.json` as a safety net.
