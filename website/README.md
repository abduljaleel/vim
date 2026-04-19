# VIM Website

A single-file static landing page for the Vulnerability Inheritance Map project.

## Stack

- Plain HTML5
- Tailwind CSS via CDN (`cdn.tailwindcss.com`)
- Google Fonts: Inter + JetBrains Mono
- No build step, no Node.js dependencies

## Local preview

```bash
# Any static file server works
python3 -m http.server --directory website 8000
# then open http://localhost:8000
```

## Deployment: GitHub Pages

Two deployment options — pick one:

### Option A — Publish from `/website` on `main` (simplest)

1. Settings → Pages → Build from branch
2. Branch: `main` · Folder: `/website`
3. Save. Site publishes at `https://abduljaleel.github.io/vim/`

### Option B — Publish from a dedicated `gh-pages` branch

```bash
git worktree add /tmp/vim-ghpages gh-pages
cp website/index.html /tmp/vim-ghpages/
cd /tmp/vim-ghpages
git add index.html && git commit -m "Publish landing page"
git push origin gh-pages
```

Then configure Settings → Pages → Build from branch `gh-pages` root.

## Custom domain (future)

When `vim-project.org` is registered:

1. Add a `CNAME` file in this directory containing the domain
2. Configure DNS: `CNAME` record pointing to `abduljaleel.github.io`
3. Enable HTTPS in Settings → Pages

## Production hardening (after sandbox acceptance)

The current page uses the Tailwind CDN for simplicity. Before claiming OpenSSF Sandbox status:

- Replace the Tailwind CDN with a self-hosted build (`tailwindcss` CLI → `dist/tailwind.css`) to eliminate the external runtime dependency
- Self-host the Google Fonts (woff2 files) to remove the `fonts.googleapis.com` connection
- Add a Subresource Integrity (SRI) hash to any remaining external scripts
- Add `Content-Security-Policy` header once served from a platform that supports it
