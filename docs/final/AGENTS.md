# Repository Guidelines

## Project Structure & Module Organization

This repository is a Typst source project for the PulseOS design document.
`main.typ` is the composition root: it imports shared configuration, renders the
cover and outline, and includes the chapters in `content/`. Keep document-wide
page, heading, and font behavior in `conf.typ`. Put reusable presentation
helpers in `components/` (`cover.typ`, `figure.typ`, `outline.typ`, and
`typography.typ`), and keep subject-specific prose in a focused file under
`content/`, such as `content/performance.typ`. Store raster assets in `img/`.
The root PDF is generated output; change the `.typ` sources rather than editing
the PDF directly.

## Build, Test, and Development Commands

Use Typst from the repository root:

```powershell
typst compile main.typ "PulseOS决赛设计文档.pdf"
typst watch main.typ "PulseOS决赛设计文档.pdf"
```

`compile` produces a fresh deliverable PDF; `watch` rebuilds it after source
changes. The document imports `@preview/lovelace:0.2.0`, so a first build may
need access to the package cache or registry. If a machine lacks the expected
Chinese fonts, pass a Typst input override such as `--input song-font=SimSun`.

## Coding Style and Naming Conventions

Follow the existing Typst style: two-space indentation inside blocks, one
argument per line in long calls, trailing commas in multi-line argument lists,
and imports at the top of a file. Name new chapter files with lowercase,
topic-based names (for example, `content/storage.typ`). Keep shared macros in
`components/`; do not duplicate page or heading formatting in chapter files.
Match the document's Chinese prose and use inline raw text for commands,
identifiers, and measurements. Do not expose raw revision identifiers when a
technical description is sufficient. No formatter or linter is
configured, so a successful compile is the required syntax check.

## Testing Guidelines

There is no automated test suite. Before submitting changes, compile the full
document and visually inspect the regenerated PDF for Chinese glyph fallback,
heading numbering, page breaks, table captions, links, and image placement.
Changes to shared configuration or components require checking every included
chapter, not only the edited page.

## Commit and Pull Request Guidelines

This checkout contains no Git metadata, so local history cannot establish an
existing commit convention. Use concise, imperative Conventional Commit-style
subjects, for example `docs: revise SMP experiment results`. Keep each commit
limited to one document concern. In a pull request, describe the content and
layout impact, link the relevant issue or evidence when available, and include
the regenerated PDF or page screenshots for visual changes. Regenerate the PDF
in the same change whenever committed source affects it.
