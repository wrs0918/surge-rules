#!/usr/bin/env python3
"""
Build and sanitize Surge rule-sets from upstream sources + curated rules.
Removes polluted shared SaaS/CDN domains (e.g. challenges.cloudflare.com, stripe.com, auth0.com)
from AI rule-sets and fixes PT/ChinaMax misclassifications.
"""

import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RULES_DIR = ROOT / "rules"
AI_DIR = RULES_DIR / "ai"

UPSTREAM = {
    "openai": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list",
    "claude": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Claude/Claude.list",
    "gemini": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list",
    "pt": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PrivateTracker/PrivateTracker.list",
}

# Shared infrastructure / SaaS domains that must NOT be hijacked by AI rule-sets
POLLUTED_SHARED_DOMAINS = {
    "algolia.net",
    "api.statsig.com",
    "auth0.com",
    "browser-intake-datadoghq.com",
    "cdn.usefathom.com",
    "challenges.cloudflare.com",
    "client-api.arkoselabs.com",
    "events.statsigapi.net",
    "featuregates.org",
    "host.livekit.cloud",
    "identrust.com",
    "intercom.io",
    "intercomcdn.com",
    "launchdarkly.com",
    "observeit.net",
    "segment.io",
    "sentry.io",
    "static.cloudflareinsights.com",
    "stripe.com",
    "turn.livekit.cloud",
    # Antigravity cloudcode must stay in Google group, never AI group
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
}

# IP/ASN rules in upstream OpenAI/Copilot lists that belong to general cloud providers (DigitalOcean/Vultr)
POLLUTED_IP_ASN = {
    "IP-ASN,14061",
    "IP-ASN,20473",
}


def fetch_lines(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-rules-sync/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        out.append(line)
    return out


def is_polluted(rule_line: str) -> bool:
    parts = [p.strip() for p in rule_line.split(",")]
    if len(parts) < 2:
        return True
    rtype, val = parts[0].upper(), parts[1].lower()
    if f"{rtype},{val.upper()}" in POLLUTED_IP_ASN:
        return True
    if val in POLLUTED_SHARED_DOMAINS:
        return True
    return False


def dedup_preserve(lines: list[str]) -> list[str]:
    seen = set()
    res = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            res.append(line)
    return res


def write_list(path: Path, title: str, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = dedup_preserve(rules)
    header = [
        f"# NAME: {title}",
        f"# TOTAL: {len(clean)}",
        "",
    ]
    path.write_text("\n".join(header + clean) + "\n", encoding="utf-8")
    print(f"Wrote {path.relative_to(ROOT)} ({len(clean)} rules)")


def build_all() -> None:
    # 1. OpenAI (ChatGPT)
    openai_up = [r for r in fetch_lines(UPSTREAM["openai"]) if not is_polluted(r)]
    openai_extra = [
        "DOMAIN-SUFFIX,chatgpt.com",
        "DOMAIN-SUFFIX,openai.com",
        "DOMAIN-SUFFIX,oaistatic.com",
        "DOMAIN-SUFFIX,oaiusercontent.com",
        "DOMAIN-SUFFIX,sora.com",
        "DOMAIN-SUFFIX,chat.com",
    ]
    write_list(AI_DIR / "OpenAI.list", "OpenAI (Cleaned)", openai_extra + openai_up)

    # 2. Claude (Anthropic)
    claude_up = [r for r in fetch_lines(UPSTREAM["claude"]) if not is_polluted(r)]
    claude_extra = [
        "DOMAIN-SUFFIX,anthropic.com",
        "DOMAIN-SUFFIX,claude.ai",
        "DOMAIN-SUFFIX,claude.com",
        "DOMAIN-SUFFIX,claudeusercontent.com",
        "DOMAIN-SUFFIX,clau.de",
        "DOMAIN-SUFFIX,claudemcpclient.com",
        "DOMAIN-SUFFIX,claudemcpcontent.com",
        "IP-CIDR,160.79.104.0/21,no-resolve",
    ]
    write_list(AI_DIR / "Claude.list", "Claude (Cleaned)", claude_extra + claude_up)

    # 3. Gemini (Google AI)
    gemini_up = [r for r in fetch_lines(UPSTREAM["gemini"]) if not is_polluted(r)]
    gemini_extra = [
        "DOMAIN,ai.google.dev",
        "DOMAIN,aistudio.google.com",
        "DOMAIN,makersuite.google.com",
        "DOMAIN,generativelanguage.googleapis.com",
        "DOMAIN,alkalicore-pa.clients6.google.com",
        "DOMAIN,alkalimakersuite-pa.clients6.google.com",
        "DOMAIN,geller-pa.googleapis.com",
        "DOMAIN,proactivebackend-pa.googleapis.com",
        "DOMAIN,robinfrontend-pa.googleapis.com",
        "DOMAIN-SUFFIX,gemini.google.com",
        "DOMAIN-SUFFIX,gemini.google",
        "DOMAIN-SUFFIX,notebooklm.google.com",
        "DOMAIN-SUFFIX,notebooklm.google",
        "DOMAIN-SUFFIX,deepmind.com",
        "DOMAIN-SUFFIX,deepmind.google",
        "DOMAIN-SUFFIX,bard.google.com",
    ]
    write_list(AI_DIR / "Gemini.list", "Gemini (Cleaned)", gemini_extra + gemini_up)

    # 4. Muse & Meta AI
    muse_rules = [
        "DOMAIN-SUFFIX,muse.ai",
        "DOMAIN-SUFFIX,meta.ai",
        "DOMAIN-SUFFIX,ai.meta.com",
        "DOMAIN-SUFFIX,metaaivm.com",
        "DOMAIN-SUFFIX,metaaiusercontent.com",
    ]
    write_list(AI_DIR / "Muse.list", "Muse & Meta AI", muse_rules)

    # 5. AI-Common (Clean Copilot + Perplexity / Cursor / Poe / OpenRouter / Groq / xAI etc.)
    ai_common_rules = [
        # Microsoft Copilot (pure domains only, without polluted OpenAI/Cloudflare entries)
        "DOMAIN,copilot.microsoft.com",
        "DOMAIN,sydney.bing.com",
        "DOMAIN-SUFFIX,edgeservices.bing.com",
        "DOMAIN,gateway.bingviz.microsoft.net",
        "DOMAIN,gateway.bingviz.microsoftapp.net",
        "DOMAIN-SUFFIX,bing-shopping.microsoft-falcon.io",
        # Other overseas AI services
        "DOMAIN-SUFFIX,perplexity.ai",
        "DOMAIN-SUFFIX,pplx.ai",
        "DOMAIN-SUFFIX,poe.com",
        "DOMAIN-SUFFIX,openrouter.ai",
        "DOMAIN-SUFFIX,groq.com",
        "DOMAIN-SUFFIX,cursor.sh",
        "DOMAIN-SUFFIX,cursor.com",
        "DOMAIN-SUFFIX,codeium.com",
        "DOMAIN-SUFFIX,windsurf.com",
        "DOMAIN-SUFFIX,mistral.ai",
        "DOMAIN-SUFFIX,cohere.com",
        "DOMAIN-SUFFIX,huggingface.co",
        "DOMAIN-SUFFIX,dify.ai",
        "DOMAIN-SUFFIX,jasper.ai",
        "DOMAIN-SUFFIX,x.ai",
        "DOMAIN-SUFFIX,grok.com",
    ]
    write_list(AI_DIR / "AI-Common.list", "AI Common (Copilot & Overseas AI)", ai_common_rules)

    # 6. PT-Direct (All direct-friendly PT sites, excluding sites blocked over domestic direct connection)
    pt_proxy_only = {"ourbits.club"}
    pt_up = []
    for r in fetch_lines(UPSTREAM["pt"]):
        parts = [p.strip() for p in r.split(",")]
        if len(parts) >= 2 and parts[1].lower() in pt_proxy_only:
            continue
        pt_up.append(r)
    pt_extra = [
        "DOMAIN-SUFFIX,chdbits.xyz",
        "DOMAIN-SUFFIX,pttime.org",
        "DOMAIN-SUFFIX,hdsky.me",
        "DOMAIN-SUFFIX,hdfans.org",
        "DOMAIN-SUFFIX,audiences.me",
    ]
    write_list(RULES_DIR / "PT-Direct.list", "PT Direct", pt_extra + pt_up)

    # 7. Proxy-Patch (High-priority proxy overrides before ChinaMax / AI rules)
    proxy_patch_rules = [
        # Keep Cloudflare Turnstile challenge widget on the main proxy to match site exit IP
        "DOMAIN-SUFFIX,challenges.cloudflare.com",
        # PT / overseas CF-protected sites whose default CF IP is blackholed over direct connection
        "DOMAIN-SUFFIX,ourbits.club",
    ]
    write_list(RULES_DIR / "Proxy-Patch.list", "Proxy Patch", proxy_patch_rules)

    # 8. Direct-Patch (High-priority direct overrides before Adblock to prevent SDK retry storms)
    direct_patch_rules = [
        # WeChat Mini-Program & image CDN falsely blocked by ad rules causing REJECT-DROP retry storms
        "DOMAIN,wxa.wxs.qq.com",
        "DOMAIN,wximg.wxs.qq.com",
        "DOMAIN,safebrowsing.urlsec.qq.com",
    ]
    write_list(RULES_DIR / "Direct-Patch.list", "Direct Patch", direct_patch_rules)


if __name__ == "__main__":
    build_all()
