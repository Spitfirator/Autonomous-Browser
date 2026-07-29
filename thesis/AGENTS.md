# Thesis instructions

These instructions apply to thesis work under this directory. The repository
root `AGENTS.md` also applies.

## Mandatory project handoff

Before outlining, drafting, revising, or checking thesis claims, read
`../sentinel/THESIS-STATUS.md`. It is the cross-project map of the current
implementation, completed AgentDojo and WASP evidence, provenance limitations,
supported interpretation, and unfinished work.

For quantitative claims, prefer curated result JSON or per-run result Markdown,
then frozen campaign provenance and task reports, then `../sentinel/EVALS.md`
and the WASP result ledger. Do not use the current Git `HEAD` as retrospective
provenance for an older run.

`../sentinel/EVALS.md` is the canonical human-readable result ledger.
`../sentinel/THESIS-STATUS.md` routes and interprets the evidence but should not
duplicate quantitative result tables.

Current thesis readiness:

- the threat model, runtime architecture, policy and audit mechanisms,
  AgentDojo evaluation, WASP evaluation, results, and non-HITL limitations are
  ready to draft;
- later benchmark reruns should update existing tables and interpretation
  without pooling incompatible provenance;
- broader HITL and plan-authority work remains incomplete, even though
  approval, handover, unresolved-sanitisation incident, trace, and extension UI
  primitives exist;
- no human-participant findings or WASP oracle results currently exist.

## Confirmed thesis direction

Use these two plain-language questions to keep the dissertation focused:

1. Can a separate enforcement layer reduce unsafe browser-agent actions without
   stopping the agent from doing useful work?
2. When that layer cannot decide safely, when and how should it pause and hand
   control to the user?

The evidence should form one connected argument:

1. AgentDojo tests the enforcement mechanisms in a controlled tool setting.
2. WASP tests whether those mechanisms transfer to a more realistic browser
   setting.
3. HITL work addresses the cases where automatic enforcement cannot resolve
   uncertainty safely.

The possible future features are easy to confuse:

- **Plan authority** would show the user a short, inspectable run plan before
  execution: what the agent intends to do, which sites or data it expects to
  use, where human help may be needed, and what it must not do. This may be
  added later as part of HITL; it is not implemented or evaluated now.
- **Provenance hiding** would deliberately withhold an entire class of
  untrusted user-generated page content from the agent based on where it came
  from, rather than trying to detect malicious wording inside it. This is only
  a possible separately labelled comparison and is not required current work.
- **Multi-agent supervision** would give one operator a queue of several agent
  runs. It remains optional future work unless it is later implemented and
  evaluated.

## Formal requirements

- Write the dissertation entirely in LaTeX, using
  `project_report - pg.tex` as the official UCL template and compilation root.
- Keep the template's current 10-point type. Do not override it with an older
  generic 12-point instruction.
- Treat 50 pages as the working limit for the complete main dissertation,
  including the HITL chapter when it is eventually written.
- Keep the complete submission, including any future appendices, at or below
  100 pages. No appendix exists yet.
- Plan and monitor the page budget while writing; do not defer length control
  until the final edit.
- `project_plan.tex` is the thesis outline, not the official report template.
- Manage references with BibTeX. There is no `.bib` or Zotero library yet, so
  create and populate a bibliography only from sources that have actually been
  verified; never invent placeholder citation records.

## Structure and argument

Treat thesis work as submission-quality academic writing. Do not trade rigour,
completeness, originality, or coherence for speed. Before substantial drafting,
inspect the relevant project evidence and establish a clear outline and
argumentative through-line appropriate to the requested chapter or section.

A conventional structure is title page, abstract, contents, introduction,
background and related work, research and results chapters, conclusion,
references, and appendices. This is a default, not a constraint: deviate when
the research is presented more clearly another way while preserving the formal
requirements.

- Address one or more challenging security problems and motivate their
  importance without exaggeration.
- Explain the state of the art, including the important peer-reviewed
  literature, and identify the precise gap the thesis addresses.
- Present the proposed approach, or explain rigorously why no solution was
  found.
- Evaluate the approach critically and in balance: where it works, where it
  fails, when another approach is preferable, and what the evidence supports
  or does not support.
- Connect the research question, threat model, design, methodology, results,
  limitations, and conclusion into one coherent argument.
- Give every section a clear purpose. Introduce concepts before relying on
  them, connect claims to evidence, use meaningful transitions, and keep
  terminology consistent.
- Avoid filler, generic boilerplate, repetitive summaries, unsupported leaps,
  and abrupt list-like prose. Explain why evidence matters, not merely what it
  contains.
- Identify further research questions discovered during the work without
  presenting unanswered questions as completed contributions.

## Originality and contributions

Make original contributions unmistakable. Include a clearly labelled
contributions subsection in the introduction unless another structure is more
effective. State exactly which ideas, questions, designs, techniques,
implementations, or findings are the author's own, without overstating them.
Restate the demonstrated contributions in the conclusion and relate each one
to the evidence presented.

## Evidence and factual integrity

- Never invent facts, results, quotations, citations, authors, venues, dates,
  identifiers, or implementation details.
- Verify quantitative and experimental claims against current code, immutable
  provenance, or curated final result artefacts. Label provisional evidence as
  provisional.
- Support external factual and comparative claims with sources that directly
  establish them. Prefer primary sources and distinguish peer-reviewed work
  from preprints.
- Cover important contrary and competing evidence; do not select literature or
  results only because they favour Sentinel.
- If a claim, reference, intended argument, or requirement cannot be verified
  or confidently resolved, ask the user before including it. Do not turn a
  plausible recollection or silent assumption into thesis prose.
- Distinguish the current implementation and measured evidence from proposed,
  feasible, or future work. Preserve the project framing and non-participant
  claim boundaries in the root instructions.
- Describe AgentDojo as controlled mechanism evidence and WASP as controlled
  browser-native transfer and limitation evidence, not deployment in the wild.
- Report legitimate utility, secure utility, native ASR, risky attempts and
  executions, interventions, false blocks, and provenance where the artifact
  supports them. Low ASR alone is not security evidence.
- Use the matched Qwen 3.5 27B WASP campaign as the principal browser-native
  comparison. Present the 9B WASP sequence as provenance-separated development
  and failure-analysis evidence: one shared off baseline, then warning-only
  enforce, sanitisation V1 enforce, and sanitisation V2 enforce.
- Treat the post-campaign browser-observation incident, bounded
  extraction/tool-result enforcement, human-only secret takeover, lifecycle
  fixes, and DOM-only interactive model path as implementation changes, not as
  results measured by the frozen AgentDojo or WASP rows.
- Treat HITL, plan authority, provenance hiding, and deterministic oracle work
  as unfinished unless a separate frozen implementation and evaluation artifact
  establishes otherwise. Scripted benchmark participant modes are not humans.

## LaTeX workflow

- Edit LaTeX source and required assets, not ignored `.log`, `.pdf`,
  `.synctex.gz`, or other generated output.
- Compile the relevant root document with Tectonic and inspect the fresh PDF,
  including page count, spacing, references, figures, tables, cross-references,
  and overflow.
- If compilation fails around an image, verify every `\includegraphics` path
  and required asset before changing the toolchain.
- A successful compilation is not sufficient: visually inspect the rendered
  document for structure, readability, and balanced use of space.
