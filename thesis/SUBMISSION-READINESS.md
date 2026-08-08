# Sentinel submission-readiness handoff

This file is a working handoff, not a source of quantitative evidence. Use the
curated result artefacts, `sentinel/EVALS.md`, and the thesis instructions for
claims and numbers.

## Submission manuscript

- Build `sentinel-submission.tex` for the requested standalone submission
  version. It uses the official UCL project-report formatting and the reviewed
  chapter sources.
- The master is deliberately an orchestration file, not a duplicate copy of
  the dissertation prose. Both `sentinel-submission.tex` and
  `project_report - pg.tex` load the shared `chapters/*.tex` sources. Review
  substantive revisions in those chapter files and compile the new master to
  obtain the submission version.
- Keep `project_report - pg.tex` as the original official-template root. Do not
  overwrite it solely to update the submission filename.
- The argument is organised around one research question and three
  contributions: executor-side mediation; post-verified observation governance
  with selective authority; and a two-environment security--utility evaluation.

## Mark-scheme alignment

The UCL project form in the author's Downloads folder assesses four areas.

1. **Background, aims, and organisation.** The introduction states one
   falsifiable research question, approach, contributions, and chapter route.
   The related-work chapter compares model-facing and system-level defences by
   trusted abstraction and enforcement boundary rather than by incomparable
   headline scores.
2. **Difficulty and achievement.** The design chapter must make the two guarded
   boundaries, central policy point, fail-closed authority protocol, audit
   invariant, BrowserUse integration, and complete artefact set explicit.
3. **Clarity.** Preserve the present sequence from authority problem, through
   threat model and design, to controlled mechanism evidence, browser transfer,
   limitations, and answer. Every figure and table must do explanatory work.
4. **Analysis and testing.** Retain paired outcomes, utility and secure utility,
   attacker attempts and executions, negative warning-only evidence, mechanism
   telemetry, provenance limits, and the technical-assurance appendix. Do not
   infer security from low attack success alone.

An 80--89% submission requires potential publishable contribution, reading
beyond the core material, original interpretation, substantial self-directed
work, and only very minor faults. Prose polish alone is insufficient; the
evidence chain and final visual QA must make those qualities easy to mark.

## Submission evidence boundary

Use the validated three-seed Qwen 3.5 27B off/policy-only/full comparison as
the principal browser-native result. Its curated JSON, generated Markdown, and
independent validator are indexed from `sentinel/EVALS.md` and
`sentinel/evals/wasp/results/README.md`.

- Keep per-seed results, between-seed variation, and exact denominators visible.
- Do not call `policy_only` a pure action-policy condition: it also retains
  boundary neutralisation and the detector warning.
- Keep the earlier single-seed 27B comparison and 9B development sequence
  provenance-separated; do not pool them with the final experiment.
- Distinguish actual human intervention from scripted `participant=none`
  outcomes.
- Treat approval, takeover, incident, Activity, and extension walkthroughs as
  implementation evidence, not participant or usability evidence.

## Completed release checks

- The final editorial pass makes the argument more direct and readable without
  weakening its scope. The abstract and research question now state the
  security--utility objective plainly; the contributions and design chapter
  explain the enforcement and authority boundaries in more natural academic
  prose; and repetitive contrasts and implementation-detail digressions have
  been removed. Tables 2.1 and 6.1--6.3 were also revised for clearer spacing,
  cross-model comparison, and a non-duplicative presentation of per-seed WASP
  effects.
- The abstract, introduction, methodology, results, discussion, conclusion, and
  assurance appendix now use the validated three-seed Qwen 3.5 27B WASP
  off/policy-only/full comparison as the principal browser-native evidence. The
  main results report aggregate and per-seed security--utility outcomes, the
  sanitisation ablation, action-audited execution, potential false blocks,
  intervention telemetry, security-by-incompetence decomposition, and the
  fixed-order limitation. The earlier single-seed 27B row and 9B sequence are
  retained only as clearly separated historical evidence and are not pooled.
- Chapter 4 introduces the ordinary Chrome-extension state before progressing
  through observation incidents, action governance, and selective human
  authority. Its runtime diagram makes the direction of data and authority
  explicit. Browser evidence is distributed by argumentative role: the
  active-run view establishes the ordinary control plane, the unresolved
  observation view sits beside the sanitisation post-condition, and the
  password handover sits in the selective-authority section. Activity, policy,
  and a bounded approval card remain supporting assurance views in Appendix A.
- The active-run and password-handover captures came from the dedicated Chrome
  instance launched by `sentinel/start.sh`. The replacement handover capture is
  local run `8d78c714`: the model navigated to a distinct synthetic login page
  and invoked `request_human_control` when it reached an empty password field.
  No password was entered or submitted, and the task was stopped after capture.
  A separate, visually distinct workspace-
  settings fixture exercised a real `unattributable` observation in run
  `0b0f1d3c`: one region was targeted, zero were changed, one security incident
  opened, and the provider-call count remained zero. The fixture contains no
  attack payload, live credential, account, private URL, or external service.
  None of the captures is benchmark, participant, or usability evidence.
- The completed Activity, policy, and approval views remain a separate
  deterministic walkthrough. Its helper passed a fresh syntax check and
  isolated API smoke test; it made no model call, started no browser agent or
  benchmark, and resolved approval, direct-takeover, and incident states to the
  expected pending authority objects. The live and deterministic servers were
  stopped after capture. Exact scope, run identifiers, reproduction commands,
  and image hashes are in `FIGURE-PROVENANCE.md`.
- Tectonic produced a 61-page A4 PDF with the expected title, author, subject,
  and keywords. Under the convention in `AGENTS.md`, the counted dissertation
  is exactly 45 pages: the Lists of Figures and Tables plus Arabic pages 1--43.
  Appendix A begins on Arabic page 44 and the bibliography on page 50, so both
  are outside that count. Concise list captions keep the List of Figures to one
  page while the full analytical captions remain beneath the figures.
- Both `sentinel-submission.tex` and the official `project_report - pg.tex`
  root compile to 61 A4 pages with identical extracted page text and page
  geometry. All pages were rendered for visual inspection, with front matter,
  affected design pages, and the appendix figure checked again at higher
  resolution. No missing references, material box warnings, or other LaTeX
  warnings remain in either final log.
- All 34 cited bibliography keys resolve one-to-one, the extracted PDF contains
  no unresolved `??` markers, and `git diff --check` passes.
- The release copy is
  `output/pdf/Sentinel-Independent-Runtime-Enforcement-for-Browser-Agents-submission-ready.pdf`
  with SHA-256
  `b6d80e59145adabb4be3ced58cd97a952787a433398b99bb5e8daf7233bd64b4`.
- The title page records the supervisor as Arthur below the submission date.

## Final gate

If any source changes after this checkpoint, compile
`sentinel-submission.tex` with Tectonic again, inspect every affected rendered
page, recheck PDF metadata and A4 geometry, confirm citations and bibliography
keys, check for missing references and material box warnings, rerun
`git diff --check`, and replace the release PDF only after those checks pass.
