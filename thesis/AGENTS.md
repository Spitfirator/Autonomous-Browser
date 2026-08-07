# Thesis instructions

These instructions apply to thesis work under this directory. The repository
root `AGENTS.md` also applies.

## Evidence routing

Before outlining, drafting, revising, or checking a claim, read
`../sentinel/THESIS-STATUS.md`. It is a concise argument and evidence map, not a
live result ledger.

For quantitative claims, use this order:

1. curated result JSON or the corresponding per-run Markdown;
2. frozen campaign provenance, task artefacts, and native scores;
3. `../sentinel/EVALS.md` and the WASP result ledger;
4. the thesis evidence map.

Do not use the current Git `HEAD` as retrospective provenance for an older
run. Do not copy result tables into instruction or status files.

## Thesis position

Use the single research question, three-part evidence chain, and contribution
wording in `../sentinel/THESIS-STATUS.md`. Do not introduce a second empirical
question or redefine the frozen baseline.

Follow that file's authority-workflow boundary: the bounded HITL implementation
is complete, while technical tests and walkthroughs are not participant
evidence. Do not infer measured comprehension, trust, workload, fatigue,
usability, or approval behaviour.

## Formal requirements

- Write in LaTeX using `project_report - pg.tex` as the official UCL template
  and compilation root. `sentinel-submission.tex` is the synchronized
  submission root.
- Use the title *Sentinel: Independent Runtime Enforcement for Browser Agents*
  everywhere, including PDF metadata.
- Use 12-point text with explicit one-and-a-half spacing.
- Target 43--45 counted pages and never exceed 45. Count everything except the
  title page, contents, abstract, acknowledgements, references, and appendices;
  the Lists of Figures and Tables are counted.
- Keep the complete submission, including appendices, at or below 100 pages.
- Manage references with BibTeX in `references.bib`. Retain only verified
  sources; never invent placeholder records.
- Keep browser-integrated figures tied to the live and deterministic local
  walkthroughs in `FIGURE-PROVENANCE.md`. Describe them as implementation
  evidence, not benchmark, participant, or usability evidence.
- Do not fabricate UI evidence or add a GenAI, Codex, or ImageGen
  acknowledgement.

## Writing and argument

- Write submission-quality academic prose with a clear argumentative
  through-line from research question to threat model, design, methodology,
  results, limitations, and conclusion.
- Explain the state of the art and the precise gap Sentinel addresses. Compare
  work by threat model, trusted abstraction, enforcement point, guarantees,
  browser applicability, evaluation strength, and limitations—not raw
  cross-paper ASR rankings.
- Make original contributions explicit without overstating them.
- Introduce concepts before relying on them, use consistent terminology, and
  explain why evidence matters.
- Remove filler, generic boilerplate, repetitive summaries, unsupported
  transitions, and list-like prose.
- Evaluate the approach critically: where it works, where it fails, and what
  the evidence does and does not establish.

## Evidence integrity

- Never invent facts, results, quotations, citations, authors, venues, dates,
  identifiers, or implementation details.
- Verify quantitative and experimental claims against curated artefacts and
  immutable provenance. Label provisional evidence explicitly.
- Prefer primary sources and distinguish peer-reviewed work from preprints.
- Include material contrary and competing evidence.
- Ask the user before including a claim, reference, requirement, or argument
  that cannot be verified or confidently resolved.
- Distinguish current implementation from the middleware version measured by
  each frozen result. A later mechanism is not retroactive benchmark evidence.
- Describe AgentDojo as controlled mechanism evidence and WASP as controlled
  browser-native transfer and limitation evidence, not deployment in the wild.
- Report utility, secure utility, native ASR, risky attempts and executions,
  interventions, false blocks, and provenance where supported. Low ASR alone
  is not security evidence.
- Keep historical and changed-provenance rows separate. Use the curated WASP
  synthesis to identify the principal comparison and the role of development
  rows.
- Scripted benchmark participant modes are controls, not people. Runtime pause
  counts, timing, and `understood` annotations are technical telemetry or
  walkthrough aids, not participant outcomes.

## LaTeX workflow

- Edit source and required assets, not ignored `.log`, `.pdf`, `.synctex.gz`,
  or other generated output.
- Keep `sentinel-submission.tex` and `project_report - pg.tex` synchronized.
- Compile both relevant roots and inspect fresh PDFs for page count, spacing,
  references, figures, tables, cross-references, overflow, metadata, and A4
  geometry.
- If compilation fails around an image, verify every `\includegraphics` path
  and required asset before changing the toolchain.
- A successful compilation is not sufficient: visually inspect the rendered
  document for structure, readability, and balanced use of space.
