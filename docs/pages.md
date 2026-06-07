<!--
Copyright 2026 SwitchMappy
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# GitHub Pages Documentation

- Japanese translation: [pages.ja.md](pages.ja.md)

The onboarding UI is a static HTML page. GitHub repository file browsing shows
the HTML source, so use GitHub Pages for the interactive language toggle:

- Published UI: <https://icecake0141.github.io/switchmappy/>
- GitHub-readable fallback: [Quick Start and User Tour](onboarding.md)

## Publishing Model

The `Pages` workflow publishes the `docs/` directory from `main`.

Required repository setting:

- Settings -> Pages -> Build and deployment -> Source: `GitHub Actions`

After the workflow completes, `docs/index.html` is available as the Pages
homepage. The Markdown pages remain available in the repository for users who
read docs directly on GitHub or in forks that do not enable Pages.

## Local Preview

Preview the same directory locally:

```bash
python -m http.server 8767
```

Then open `http://127.0.0.1:8767/docs/`.
