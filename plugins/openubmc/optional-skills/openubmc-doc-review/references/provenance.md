# Analyzer provenance

The bundled deterministic analyzers were consolidated from the document Skills
installed from:

- distribution: `https://gitcode.com/openUBMC/skills-marketplace.git`
- distribution path: `skills/doc-skills`
- inspected distribution revision: `5e7075b435aeebe8b34d708d2b47e5567bcddab7`
- upstream author project identified in distribution history:
  `https://gitcode.com/hufuxing/Docs-SKILL.git`

Internal analyzer mapping:

- `security`: `doc-security-sensitive-tester`
- `links`: `doc-links-tester`
- `typo`: `doc-typo-tester`
- `spelling`: `doc-spelling-tester`
- `punctuation`: `doc-punctuation-tester`
- `cli`: `doc-cli-tester`
- `consistency`: `doc-documentation-product-consistency-tester`

The former orchestrator, scoring, completeness, TEGR, structure, and readability
Skills were not retained as nested Skill interfaces. Their useful review criteria
were consolidated into this Skill's profile and content references.

The content and report references also incorporate the reviewed main-branch
criteria at `1f016fd13d6999599bb8d011265cc6238f0059e3` from
`agent-doc-completeness`, `agent-doc-correctness`, `agent-doc-readability`,
`doc-documentation-product-consistency-tester`, `doc-quality-auditor-human`,
`doc-quality-auditor`, `doc-structure-meta-tester` and `doc-tegr-content-tester`.
Local adaptations use applicable checks with evidence, explicit lane/claim states
and versioned inventory mappings. Numeric SEO quotas and fixed scoring are absent.
Scanner execution is separate from command execution and semantic verification.
