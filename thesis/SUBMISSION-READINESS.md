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
  with selective authority; and a two-benchmark security--utility evaluation.

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
- In `full`, the detector still triggers observation sanitisation and action
  policy remains active. A confirmed removal reaches the model without a
  warning; an unresolved observation is withheld. Accordingly, full versus
  policy-only measures the configured sanitisation treatment, not warning
  suppression independently of removal.
- Keep the earlier single-seed 27B comparison and 9B development sequence
  provenance-separated; do not pool them with the final experiment.
- Distinguish actual human intervention from scripted `participant=none`
  outcomes.
- Treat approval, takeover, incident, Activity, and extension walkthroughs as
  implementation evidence, not participant or usability evidence.

## Completed release checks

- The final narrative pass rewrites Design and Implementation and Evaluation
  Methodology as continuous arguments. Chapter 4 now walks Figure 4.1 from task
  to browser effect and back to the planner, follows one governed step in
  runtime order, and connects the control plane, observation guard, action
  guard, selective authority, audit, and later evaluation. Chapter 5 now moves
  explicitly from component replay to controlled AgentDojo effects and then to
  browser-native WASP transfer. It also identifies the fixed system-level
  security guidance in AgentDojo's enforced condition and limits causal
  attribution to the complete governed configuration. Repetitive protocol
  detail was removed rather than compressed through typography or spacing.
- The introduction gives AgentDojo appropriate quantitative weight before the
  principal three-seed WASP result. The background presents AgentDojo and WASP
  as complementary but non-poolable evidence and adds balanced primary
  literature on SecAlign and learned surface heuristics. Selected within-paper
  results now quantify the SecAlign and Task Shield security--utility claims,
  alongside the later benign-refusal evidence, without treating values from
  different agent stacks as a leaderboard. It treats model
  training and runtime enforcement as potentially complementary intervention
  points, explicitly as an architectural synthesis that was not evaluated,
  without making an unverified operational comparison. IPIGuard and VIGIL add
  peer-reviewed examples of planned tool-dependency and verify-before-commit
  enforcement. AttriGuard adds the close contemporary comparison of
  counterfactual causal attribution at the action boundary, while MUZZLE gives
  the proposed browser-specific adaptive evaluation a concrete trajectory-guided
  method. Progent, Task Shield, MELON, and Fides are stated accurately.
  Table 6.1 now
  uses the conventional five-column model/condition/outcome layout, and the
  limitations section contains a named ethics and responsible-research
  subsection.
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
  authority. Its runtime diagram and surrounding narrative make both the action
  and observation directions explicit. The text-only boundary now states that
  screenshots are excluded from the evaluated model-input path, pixel-only
  instructions therefore do not enter that channel, and a multimodal extension
  would need its own visual guard. Figure 4.5 places Approval and Activity views
  beside the authority and audit discussion; the policy screenshot is omitted
  because the policy and authority tables explain enforcement more directly.
  Activity's timing, pause counts, and per-decision `understood` markers now
  provide initial instrumentation for a future human-in-the-loop study.
  Discussion identifies that study as the next step after the dissertation,
  while also stating the preparation required before participant research and
  keeping human effectiveness outside the evidence reported here.
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
- The approval and Activity views come from the deterministic local
  walkthrough. Their concise source mapping, reproduction commands, and image
  hashes are in `FIGURE-PROVENANCE.md`.
- Tectonic produced a 66-page A4 PDF with the expected title, author, subject,
  and keywords. Under the formal exclusions supplied for the dissertation, the
  counted text is exactly 50 pages and meets the 50-page ceiling: the Lists of
  Figures and Tables plus Arabic pages 1--48. Appendix A begins on Arabic page
  49 and the bibliography on page 54, so both are outside that count. Concise
  captions keep the Lists of Figures and Tables compact and leave detailed
  interpretation in the surrounding prose.
- Both `sentinel-submission.tex` and the official `project_report - pg.tex`
  root compile to 66 A4 pages with identical extracted page text and page
  geometry. All pages were rendered for visual inspection, with front matter,
  Figure 4.1, the control-plane views, the result tables and graph, the ethics
  subsection, and the assurance appendix checked again at higher
  resolution. No missing references, material box warnings, or other LaTeX
  warnings remain in either final log.
- The root-level PDFs have been regenerated from those canonical sources, so
  they now include Progent, SecAlign, Task Shield, MELON, IPIGuard, VIGIL,
  AttriGuard, MUZZLE, and the final warning semantics rather than the earlier
  61-page text.
- All 41 cited bibliography keys resolve one-to-one, the extracted PDF contains
  no unresolved `??` markers or em dashes, and `git diff --check` passes.
- The release copy is
  `output/pdf/Sentinel-Independent-Runtime-Enforcement-for-Browser-Agents-submission-ready.pdf`
  with SHA-256
  `eeabf2cd94371baea1611452c79f5148c99864d13d7a60d43eea1abc77eddf06`.
- The title page records the supervisor as Arthur below the submission date.

## Final gate

If any source changes after this checkpoint, compile
`sentinel-submission.tex` with Tectonic again, inspect every affected rendered
page, recheck PDF metadata and A4 geometry, confirm citations and bibliography
keys, check for missing references and material box warnings, rerun
`git diff --check`, and replace the release PDF only after those checks pass.
