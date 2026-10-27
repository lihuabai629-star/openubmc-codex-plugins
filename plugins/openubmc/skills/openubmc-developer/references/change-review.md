# Source change review

Review the requested diff against repository standards and the originating
requirement. Follow callers, registrations and data only far enough to establish
each finding; inspect surrounding unchanged code when it determines the result.

## Evidence for each finding

- Cite the changed location, concrete trigger or documented rule, relevant
  caller/data flow, consequence if left unchanged, and smallest correction.
  Establish defects with an observed failure or a source trace. Identify
  unresolved assumptions as evidence gaps. For style requirements, cite the
  rule and hunk without inventing a runtime failure.
- For changed loops, async paths or collections, inspect reachable workloads
  for races, duplicate work, unbounded retention, repeated hot-loop work and
  quadratic growth. Support performance claims with input size, lifetime and
  call frequency from source or measurements.
- Judge wrappers, unused options and single-implementation abstractions by
  actual callers and responsibilities. Preserve boundaries that own credentials,
  platform adaptation, lifecycle or test substitution, along with compatibility,
  external and MDB/MDS registrations, authored/generated chains, error handling,
  trust-boundary validation and hardware behavior. Line count alone does not
  establish an improvement.

## Report two independent views

**Standards:** cite the applicable repository rule for a violation. Treat code
smells as optional suggestions until evidence establishes a concrete defect;
repository conventions take precedence. Consolidate duplicated logic only when
behavior and lifetimes match, at the layer responsible for the shared rule.

**Spec:** cite the requirement for missing or partial behavior, incorrect
implementation, or scope expansion. Use the user's established task contract
when there is no separate specification; disclose any remaining ambiguity.

Within each view, separate required corrections from optional simplification
suggestions. Report evidence gaps separately. If work is delegated, pass the full
evidence criteria and relevant source/requirement identities to each reviewer.
Do not merge the views into one score or invent defects to fill either view.

Adapted from [Ponytail v5.3.2](https://github.com/DietrichGebert/ponytail/tree/09c434ab73ca43761c5d8b0c5d341926c2fba710),
commit `09c434ab73ca43761c5d8b0c5d341926c2fba710`, under the
[MIT license](../resources/community/ponytail/LICENSE).
