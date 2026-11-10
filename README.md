# Surge Rules

Self-hosted, sanitized Surge `RULE-SET` lists with automated weekly upstream sync (`sync.py`).
Every policy group in Surge maps 1-to-1 to a single `.list` file in this repository—no external third-party URLs or separate patch lists required.

## Rule Sets (`rules/`)

- `Ads.list` — AWAvenue Ads minus WeChat false positives + browser DoH block (`chrome.cloudflare-dns.com`)
- `ai/OpenAI.list` — OpenAI / ChatGPT / Sora (cleaned of shared SaaS/CDN domains)
- `ai/Claude.list` — Anthropic / Claude
- `ai/Gemini.list` — Google Gemini / AI Studio / NotebookLM / DeepMind / Antigravity (`cloudcode-pa`)
- `ai/Muse.list` — Muse AI & Meta AI
- `ai/AI-Common.list` — Microsoft Copilot (pure) & common overseas AI (Perplexity, Cursor, Poe, OpenRouter, Groq, xAI)
- `Telegram.list` — Telegram
- `Twitter.list` — Twitter / X
- `Social.list` — Facebook + Instagram + Discord + Reddit combined
- `YouTube.list` — YouTube
- `Netflix.list` — Netflix
- `Disney.list` — Disney+
- `GlobalMedia.list` — Overseas streaming media
- `ChinaMedia.list` — BiliBili + ChinaMedia combined
- `Game.list` — Steam + Epic + Sony + Nintendo combined
- `Apple.list` — Apple services
- `Microsoft.list` — Microsoft services
- `Google.list` — Google services
- `ChinaMax.list` — ChinaMax + direct-friendly PT sites + tracker keywords (with CF-blackholed PT sites removed at source)
- `Proxy.list` — Global Proxy + GitHub + Cloudflare Turnstile (`challenges.cloudflare.com`) + CF-protected PT sites (`ourbits.club`, `chdbits.xyz`, `hdfans.org`)
