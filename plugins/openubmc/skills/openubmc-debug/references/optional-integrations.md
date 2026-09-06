# Optional Integrations

Personal memory, note vaults, NotebookLM, and similar user-specific services are disabled by default.

The standalone openUBMC KB is governed separately by the Knowledge Routing reference. When it is
already configured and available, it may provide a
non-blocking candidate route without becoming diagnostic evidence.

Enter this branch only when the user explicitly requests or configures the integration. A
cross-Skill handoff may preserve that explicit opt-in, but it must never infer or add the opt-in.

Require runtime-provided configuration such as tool/endpoint, resource or notebook identifier, and output directory. Do not infer install roots, server URLs, notebook IDs, vault locations, or user identities from examples.

Run optional lookups in parallel with the evidence path when useful. Treat their output as background that must map back to source, object, alarm, log, or file evidence. Authentication failure, missing tools, empty answers, and timeouts never block or downgrade a completed evidence path.

When the user requests a note, write only to the destination they supplied and redact credentials, tokens, private paths, IPs, and incident-specific identifiers as required. Note creation is not part of the diagnostic completion criterion.
