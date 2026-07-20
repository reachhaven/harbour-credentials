# Repository Guidelines

**[CLAUDE.md](CLAUDE.md) is the single canonical instruction file for this
repository.** Read it before making changes — it covers the trust model
(ADR-006), commands, architecture, dual-runtime parity rules, standards
compliance, coding conventions, and the commit/PR workflow. This file and
`.github/copilot-instructions.md` are intentionally thin pointers so the
guidance cannot drift apart.

Non-negotiables (duplicated here so no tool can miss them — full detail in
CLAUDE.md):

1. **Commits**: sign with `-s -S` (Signed-off-by + GPG); conventional-commit
   format; **never any AI attribution or mention of AI tools** in commit
   messages; author is a human developer with their official email.
2. **Commit/PR preparation**: write `.playground/commit-message.md` and
   `.playground/pr-description.md` first; only commit/push/open a PR after
   explicit human confirmation in the current session.
3. **Standards compliance**: schemas, examples, and DID documents must align
   with the specs in `docs/specs/references/` (LinkML files carry bracketed
   citation tags); **never use `range: Any` in LinkML**; run
   `make validate shacl` and `make story` before committing schema or
   example changes.
4. **Dual runtime parity**: a change to one runtime almost always needs the
   mirror change in the other, plus an interop test.
