# Portfolio Site — Setup Guide

This `docs/` folder is the GitHub Pages source for the portfolio.

## Structure

```
docs/
├── index.html      ← Cyber skills page (landing page — 5 Claude Skills + live demos)
├── data.html       ← Data/ML roadmap page (shipped skills + cert timeline)
├── game.html       ← MITRE Matcher — interactive ATT&CK technique quiz (15 scenarios)
├── assets/
│   ├── style.css   ← All shared styling
│   ├── site.js     ← Nav state + scroll reveals
│   └── demos.js    ← Terminal animation engine (loaded on cyber page only)
└── README.md       ← This file
```

Three-page site: visitors land on the cyber skills showcase. The Data page shows the roadmap. The Play page is an interactive MITRE ATT&CK technique-matching game with 15 real-world attacker behavior scenarios — shipped with full explanations for each answer.

## Deploy in 60 seconds

1. Push this repo to GitHub (public repo)
2. **Settings** → **Pages**
3. Source: `Deploy from a branch`, Branch: `main`, Folder: `/docs`
4. **Save**
5. Wait ~30 seconds, visit `https://<yourusername>.github.io/cyber-skills/`

## Before you push — replace placeholders

Search and replace `yourusername` → your GitHub handle across all three HTML files.

From the `docs/` folder in PowerShell:

```powershell
foreach ($f in @("index.html","data.html","game.html")) {
  (Get-Content $f) -replace "yourusername", "<your-handle>" | Set-Content $f
}
```

Or just open each file and use Ctrl+H.

## Adding or editing content

### To add a new skill to the cyber page

Edit `index.html`, copy one of the `<div class="skill">...</div>` blocks, and:

1. Change the number (`05 /`, `06 /` etc.)
2. Update title, description, tags, stack
3. Change the `data-target` and `id` values to `demo-5`, `demo-6`...
4. Add a matching entry in `assets/demos.js` inside the `demos` object

### To move a data skill from "coming soon" to "shipped"

In `data.html`, remove the `soon-card` entry for that skill. Copy the cyber-skill block structure into `index.html` (or create a dedicated section on the data page) and wire up a new demo in `demos.js`.

### To add/edit MITRE Matcher game questions

All 15 questions live inside `game.html` as a `questions` array in the inline `<script>`. Each entry is:

```javascript
{
  scenario: "Plain-English description of the attacker behavior",
  evidence: "Command line / log line / IOC (shown in monospace box)",
  options: [
    { code: "T1059.001", name: "PowerShell" },
    { code: "T1055",     name: "Process Injection" },
    { code: "T1218",     name: "Signed Binary Proxy Execution" },
    { code: "T1105",     name: "Ingress Tool Transfer" },
  ],
  correct: 0,   // index into options (0-3)
  explain: "Why the right answer is right — supports <code>inline code</code> and <strong>emphasis</strong>."
}
```

To add a 16th question: append a new object to the `questions` array, update the header subtitle if needed. No other changes required — the game auto-adapts to any question count.

### To add a fourth page (e.g., research.html, projects.html)

1. Copy `data.html` as a template (simpler than index.html, no demos)
2. Change the `<body class="...">` class to something like `page-research`
3. Add a new `<a>` entry to the `<div class="nav-links">` in **all three existing pages**
4. The active-link highlighting works automatically — just add `data-page="research.html"` to the nav link

### To change colors

All tokens are CSS variables at the top of `assets/style.css`:

```css
--accent-a: #ff4d9d;    /* cyber: pink */
--accent-b: #7c3aed;    /* shared: violet */
--accent-c: #06d6a0;    /* cyber: mint (success color) */
--accent-d: #ffd166;    /* shared: amber (warnings) */
--accent-blue: #4cc9f0; /* data: blue */
```

The data page automatically uses blue-tinted orbs/accents because its body has `class="page-data"`.

## Custom domain (optional)

If you own a domain:

1. Create a file named `CNAME` (no extension) in `docs/` containing just your domain (e.g. `augustine.sec`)
2. DNS: CNAME record pointing to `<yourusername>.github.io`
3. GitHub Pages settings → Custom domain field → enter your domain
4. Enable "Enforce HTTPS"
