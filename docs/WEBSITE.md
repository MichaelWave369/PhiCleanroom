# PhiCleanroom public React site

The repository includes a standalone, mobile-responsive React/Vite site in web/.
It is an explanatory front-end **only**. It cannot read the investigator's local
vault, approve real rules, run REA, or authorize releases. The Evidence Lab section
uses a pure deterministic simulation implemented in web/src/demoGate.js.
The **Anti-M Completion Console** is a separate read-only browser-local v1 completion-contract/receipt/source digest reconciler with a synthetic demo, not a signed approval checker or Vault backend. See [ANTI_M_CONSOLE.md](ANTI_M_CONSOLE.md).

The **Local Inspector** section is a separate browser-local v2 candidate viewer that computes actual SHA-256 digests for user-selected files; it never approves real rules or communicates with the private vault. See [BROWSER_INSPECTOR.md](BROWSER_INSPECTOR.md).

## Local development

Requires Node.js 22+ and npm.

    cd web
    npm install
    npm test
    npm run dev

Local Vite URL should include the configured /PhiCleanroom/ base path.
Build a static site with:

    npm run build

The built files live in web/dist/ and are gitignored.

## GitHub Pages deployment

1. Merge the website pull request into main.
2. In the GitHub repository open **Settings > Pages** and select **GitHub Actions** as the source, if it is not already selected. This is a repository-owner setting, not something the site can change.
3. Open **Actions > PhiCleanroom React Pages** and inspect the build/deploy jobs. A manual run via workflow_dispatch is available if the automatic run was skipped or Pages was enabled afterwards.
4. Once GitHub reports successful deployment, open https://michaelwave369.github.io/PhiCleanroom/.

GitHub Pages may need to be enabled/configured before deployment can succeed.
Until a completed deployment is observed, the address above is the **expected
URL**, not a confirmed live website.

The Vite base is /PhiCleanroom/ for repository-path deployment, not /.
Changing the repository name or deploying to a user-site root requires updating
web/vite.config.js and the hardcoded favicon path in web/index.html.

## Workflow and scope

.github/workflows/pages.yml runs the site's deterministic tests and Vite
build on pull requests, and publishes web/dist from main using the official
GitHub Pages artifact and deployment actions. Existing Python tests are not
replaced by this site workflow.

The site uses Google Fonts when available. Local system fallbacks keep it usable
if the font service is inaccessible.

## Security and integrity

- The Evidence Lab demo never sends input to an API. Its switches alter local React state.
- The Anti-M console hashes locally selected completion/receipt/source files and checks declared link consistency, but cannot independently verify the private ledger, tests, provenance or human identity.
- The Local Inspector reads chosen JSON and artifact files with browser File APIs and Web Crypto, comparing SHA-256 hashes entirely in memory, without uploading files or saving local data.
- Toggling approval in the demo is **not** a real authenticated human signature.
- No evidence artifacts, investigation logs, original software, secrets, or local
  Vault contents should be committed to the public repository.
- A browser digest match is not proof of behavioral correctness or authorization.
- Actual process-level isolation, builder implementation and code mutation
  runner remain roadmap items. The UI differentiates live CLI functionality
  from planned capabilities.
- Authorized investigation only. Clean-room separation is not a guarantee that
  software is free of intellectual property, licensing or contract restrictions.
