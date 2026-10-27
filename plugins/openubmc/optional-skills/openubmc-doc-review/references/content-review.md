# Content, structure, and readability

## Classify before judging completeness

Use the TEGR document types:

- **Tutorial** teaches a beginner through a complete learning path.
- **How-to guide** helps an informed reader accomplish one concrete goal.
- **Reference** describes interfaces, parameters, values, errors, and constraints.
- **Explanation** builds understanding of concepts, architecture, or design choices.

Mixed documents are not automatically defective. Report mixing only when it obscures
the reader's goal or causes required material to disappear.

## Document-set completeness

Evaluate whether the set covers the user journey rather than requiring all four types
unconditionally. Look for:

- an entry point and a usable next step;
- coverage of important user tasks;
- reference coverage for public interfaces, configuration, and errors;
- explanations for concepts that cannot be understood from procedure alone;
- navigation among related document types;
- version, compatibility, ownership, and lifecycle metadata where applicable.

Use known features or an extracted interface inventory as the denominator. Without a
credible denominator, describe gaps qualitatively and lower confidence.

For full/release review, use [completeness checks](completeness-checks.md) for the
stable check IDs and inventory mapping. Review a single document against its own
scope; whole-set coverage requires a versioned inventory and actual navigation.

## Single-document completeness

Apply only the checks relevant to its type:

- purpose, audience, scope, prerequisites, and applicability;
- ordered steps and expected results for tutorials/how-to guides;
- a final verification and common failure handling for operational procedures;
- parameter type, requirement, default, constraints, return values, and errors for
  reference entries;
- context, rationale, trade-offs, and links to action/reference material for
  explanations;
- examples that are complete enough to use and do not conceal required values.

## Human readability

Prioritize nine practical qualities: the reader can identify the goal, find the
needed information, understand prerequisites, follow the sequence, distinguish
examples from required input, recognize success, recover from likely failures,
understand terminology, and find the next relevant document.

Prefer concrete findings tied to reader cost. Do not fail prose merely for style
preference, search-engine optimization, author biography, or a universal readability
score.

Use [readability and evidence](readability-and-evidence.md) for human-first review
and technical claims. Record applicable checks as Pass/Partial/Fail with a location
and reason, without averaging them into an unsolicited score.
