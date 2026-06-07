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

# GitHub Pages ドキュメント

- English original: [pages.md](pages.md)

オンボーディングUIは静的HTMLです。GitHubリポジトリの通常ファイル表示では
HTMLソースとして表示されるため、言語トグル付きUIはGitHub Pagesで公開します。

- 公開UI: <https://icecake0141.github.io/switchmappy/>
- GitHub上で読めるfallback: [クイックスタートとユーザツアー](onboarding.ja.md)

## 公開方式

`Pages` workflow が `main` の `docs/` ディレクトリを公開します。

必要なリポジトリ設定:

- Settings -> Pages -> Build and deployment -> Source: `GitHub Actions`

workflow完了後、`docs/index.html` がPagesのトップページとして公開されます。
Markdownページは、GitHub上で直接読む利用者やPagesを有効化していないfork向けに
残します。

## ローカルプレビュー

同じディレクトリをローカルでプレビューできます。

```bash
python -m http.server 8767
```

その後、`http://127.0.0.1:8767/docs/` を開きます。
