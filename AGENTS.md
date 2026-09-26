# Blinder working requirements

Read [the content contract](docs/content-contract.md) before changing rewriting, masking or consumer-visible responses. This records the operator's delivery requirements and applies to all contributors, including Codex and Claude.

- Treat replacement content as product behavior, not incidental copy. Generated page content must use neutral filler, never removal/status labels such as `REDACTED`, `[removed]`, `[image]` or `Blinder: title removed`.
- Keep ordinary display prose separate from functional values. Use the existing session-dependent prose for display; preserve reversible mappings for submitted values, cookies, paths and other application data. Do not substitute prose into executable syntax or functional fields.
- Do not delete genuine upstream diagnostics or application data merely because they contain a word used by an old placeholder. Preserve status, errors, reflected input, security-control decisions, malformed grammar and observable changes.
- Target each response's original decoded byte size without falsifying Content-Length or destroying structure/evidence. Record real mismatches and finite replacement-capacity limits.
- Generated filler must also be checked against configured identities. A corpus word that happens to be a configured brand/name must not be reintroduced by replacement.
- Retain explicit transformation provenance and measurements in response metadata and operator evidence. Neutral page content is not a promise that transformation is undetectable.
- For a runtime report, inspect the actual listener process and build revision. Passing source tests or building a new binary does not update an already-running process. Distinguish source, built artifact and serving process in the result.
- Use local verification and preserve captured evidence. Do not push or replace a live session merely because a build passed; follow the current user authorization and keep pending browser/Tor acceptance explicit.
