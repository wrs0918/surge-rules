# Surge Rules

Curated and sanitized Surge `RULE-SET` lists with automated upstream sync (`sync.py`).

## Rule Sets

- `rules/ai/OpenAI.list` — OpenAI / ChatGPT / Sora (cleaned of shared SaaS/CDN domains)
- `rules/ai/Claude.list` — Anthropic / Claude
- `rules/ai/Gemini.list` — Google Gemini / AI Studio / NotebookLM / DeepMind
- `rules/ai/Muse.list` — Muse AI & Meta AI
- `rules/ai/AI-Common.list` — Microsoft Copilot (pure) & common AI services (Perplexity, Cursor, Poe, OpenRouter, Groq, xAI)
- `rules/PT-Direct.list` — Direct-friendly Private Tracker domains
- `rules/Proxy-Patch.list` — High-priority proxy overrides (Cloudflare Turnstile consistency & blocked CF sites)
- `rules/Direct-Patch.list` — High-priority direct whitelist before ad-blockers
