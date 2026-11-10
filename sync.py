#!/usr/bin/env python3
"""
Build and sanitize ALL Surge rule-sets into wrs0918/surge-rules.
Eliminates the need for separate patch lists by sanitizing ChinaMax, Proxy, Ads, and AI lists at build time.
"""

import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RULES_DIR = ROOT / "rules"
AI_DIR = RULES_DIR / "ai"

BM7 = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge"

UPSTREAM = {
    "ads": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/refs/heads/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET.list",
    "openai": f"{BM7}/OpenAI/OpenAI.list",
    "claude": f"{BM7}/Claude/Claude.list",
    "gemini": f"{BM7}/Gemini/Gemini.list",
    "telegram": f"{BM7}/Telegram/Telegram.list",
    "twitter": f"{BM7}/Twitter/Twitter.list",
    "social": [
        f"{BM7}/Facebook/Facebook.list",
        f"{BM7}/Instagram/Instagram.list",
        f"{BM7}/Discord/Discord.list",
        f"{BM7}/Reddit/Reddit.list",
    ],
    "youtube": f"{BM7}/YouTube/YouTube.list",
    "netflix": f"{BM7}/Netflix/Netflix.list",
    "disney": f"{BM7}/Disney/Disney.list",
    "global_media": f"{BM7}/GlobalMedia/GlobalMedia_All_No_Resolve.list",
    "china_media": [
        f"{BM7}/BiliBili/BiliBili.list",
        f"{BM7}/ChinaMedia/ChinaMedia.list",
    ],
    "game": [
        f"{BM7}/Steam/Steam.list",
        f"{BM7}/Epic/Epic.list",
        f"{BM7}/Sony/Sony.list",
        f"{BM7}/Nintendo/Nintendo.list",
    ],
    "apple": f"{BM7}/Apple/Apple_All_No_Resolve.list",
    "microsoft": f"{BM7}/Microsoft/Microsoft.list",
    "google": f"{BM7}/Google/Google.list",
    "pt": f"{BM7}/PrivateTracker/PrivateTracker.list",
    "chinamax": f"{BM7}/ChinaMax/ChinaMax_All.list",
    "proxy": [
        f"{BM7}/GitHub/GitHub.list",
        f"{BM7}/Proxy/Proxy_All_No_Resolve.list",
    ],
}

# 1. Shared SaaS / CDN domains that must NOT be hijacked by AI rule-sets
POLLUTED_AI_DOMAINS = {
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
}

POLLUTED_AI_IP_ASN = {
    "IP-ASN,14061",
    "IP-ASN,20473",
}

# 2. Domains falsely blocked by upstream Ad rules (causes WeChat SDK retry storms)
ADS_WHITELIST_DOMAINS = {
    "wxa.wxs.qq.com",
    "wximg.wxs.qq.com",
    "safebrowsing.urlsec.qq.com",
}

# 3. Overseas Cloudflare-protected sites that are blackholed over domestic direct connection
#    Must be excluded from Direct/ChinaMax/PT-Direct and placed into Proxy.list
FORCE_PROXY_DOMAINS = {
    "ourbits.club",
    "chdbits.xyz",
    "hdfans.org",
    "challenges.cloudflare.com",
    "githubusercontent.com",
}


def fetch_lines(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-rules-sync/2.0"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        out.append(line)
    return out


def extract_target(rule_line: str) -> tuple[str, str]:
    parts = [p.strip() for p in rule_line.split(",")]
    if len(parts) < 2:
        return "", ""
    return parts[0].upper(), parts[1].lower().lstrip(".")


def is_ai_polluted(rule_line: str) -> bool:
    rtype, val = extract_target(rule_line)
    if not rtype:
        return True
    if f"{rtype},{val.upper()}" in POLLUTED_AI_IP_ASN:
        return True
    if val in POLLUTED_AI_DOMAINS:
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
    # 1. Ads (AWAvenue Ads minus WeChat false positives + Chrome DoH block)
    ads_up = []
    for r in fetch_lines(UPSTREAM["ads"]):
        _, val = extract_target(r)
        if val in ADS_WHITELIST_DOMAINS:
            continue
        ads_up.append(r)
    ads_extra = [
        # Block browser built-in DoH so Chrome falls back to Surge Fake-IP DNS immediately
        "DOMAIN,chrome.cloudflare-dns.com",
    ]
    write_list(RULES_DIR / "Ads.list", "Ads & DoH Block (Cleaned)", ads_extra + ads_up)

    # 2. AI Lists
    openai_up = [r for r in fetch_lines(UPSTREAM["openai"]) if not is_ai_polluted(r)]
    openai_extra = [
        "DOMAIN-SUFFIX,chatgpt.com",
        "DOMAIN-SUFFIX,openai.com",
        "DOMAIN-SUFFIX,oaistatic.com",
        "DOMAIN-SUFFIX,oaiusercontent.com",
        "DOMAIN-SUFFIX,sora.com",
        "DOMAIN-SUFFIX,chat.com",
    ]
    write_list(AI_DIR / "OpenAI.list", "OpenAI (Cleaned)", openai_extra + openai_up)

    claude_up = [r for r in fetch_lines(UPSTREAM["claude"]) if not is_ai_polluted(r)]
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

    gemini_up = [r for r in fetch_lines(UPSTREAM["gemini"]) if not is_ai_polluted(r)]
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
        "DOMAIN,cloudcode-pa.googleapis.com",
        "DOMAIN,daily-cloudcode-pa.googleapis.com",
        "DOMAIN-SUFFIX,cloudcode-pa.googleapis.com",
        "DOMAIN-SUFFIX,gemini.google.com",
        "DOMAIN-SUFFIX,gemini.google",
        "DOMAIN-SUFFIX,notebooklm.google.com",
        "DOMAIN-SUFFIX,notebooklm.google",
        "DOMAIN-SUFFIX,deepmind.com",
        "DOMAIN-SUFFIX,deepmind.google",
        "DOMAIN-SUFFIX,bard.google.com",
    ]
    write_list(AI_DIR / "Gemini.list", "Gemini & Antigravity (Cleaned)", gemini_extra + gemini_up)

    muse_rules = [
        "DOMAIN-SUFFIX,muse.ai",
        "DOMAIN-SUFFIX,meta.ai",
        "DOMAIN-SUFFIX,ai.meta.com",
        "DOMAIN-SUFFIX,metaaivm.com",
        "DOMAIN-SUFFIX,metaaiusercontent.com",
    ]
    write_list(AI_DIR / "Muse.list", "Muse & Meta AI", muse_rules)

    ai_common_rules = [
        "DOMAIN,copilot.microsoft.com",
        "DOMAIN,sydney.bing.com",
        "DOMAIN-SUFFIX,edgeservices.bing.com",
        "DOMAIN,gateway.bingviz.microsoft.net",
        "DOMAIN,gateway.bingviz.microsoftapp.net",
        "DOMAIN-SUFFIX,bing-shopping.microsoft-falcon.io",
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

    # 3. Social Media
    write_list(RULES_DIR / "Telegram.list", "Telegram", fetch_lines(UPSTREAM["telegram"]))
    write_list(RULES_DIR / "Twitter.list", "Twitter / X", fetch_lines(UPSTREAM["twitter"]))
    social_rules = []
    for u in UPSTREAM["social"]:
        social_rules.extend(fetch_lines(u))
    write_list(RULES_DIR / "Social.list", "Social Media Combined", social_rules)

    # 4. Streaming Media
    write_list(RULES_DIR / "YouTube.list", "YouTube", fetch_lines(UPSTREAM["youtube"]))
    write_list(RULES_DIR / "Netflix.list", "Netflix", fetch_lines(UPSTREAM["netflix"]))
    write_list(RULES_DIR / "Disney.list", "Disney+", fetch_lines(UPSTREAM["disney"]))
    write_list(RULES_DIR / "GlobalMedia.list", "Global Media", fetch_lines(UPSTREAM["global_media"]))
    cn_media_rules = []
    for u in UPSTREAM["china_media"]:
        cn_media_rules.extend(fetch_lines(u))
    write_list(RULES_DIR / "ChinaMedia.list", "China Media Combined", cn_media_rules)

    # 5. Game & Big Tech
    game_rules = []
    for u in UPSTREAM["game"]:
        game_rules.extend(fetch_lines(u))
    write_list(RULES_DIR / "Game.list", "Game Platforms Combined", game_rules)
    write_list(RULES_DIR / "Apple.list", "Apple", fetch_lines(UPSTREAM["apple"]))
    write_list(RULES_DIR / "Microsoft.list", "Microsoft", fetch_lines(UPSTREAM["microsoft"]))
    write_list(RULES_DIR / "Google.list", "Google", fetch_lines(UPSTREAM["google"]))

    # 6. Proxy (GitHub + Proxy_All + CF Turnstile & blocked PT sites)
    proxy_rules = [
        "DOMAIN-SUFFIX,githubusercontent.com",
        "DOMAIN-SUFFIX,challenges.cloudflare.com",
        "DOMAIN-SUFFIX,ourbits.club",
        "DOMAIN-SUFFIX,chdbits.xyz",
        "DOMAIN-SUFFIX,hdfans.org",
    ]
    for u in UPSTREAM["proxy"]:
        proxy_rules.extend(fetch_lines(u))
    write_list(RULES_DIR / "Proxy.list", "Global Proxy (Cleaned)", proxy_rules)

    # 7. ChinaMax / Direct (PT-Direct + ChinaMax minus FORCE_PROXY_DOMAINS)
    direct_rules = [
        "DOMAIN,wxa.wxs.qq.com",
        "DOMAIN,wximg.wxs.qq.com",
        "DOMAIN,safebrowsing.urlsec.qq.com",
        "IP-CIDR,162.159.128.0/18,no-resolve",
        "DOMAIN-SUFFIX,pttime.org",
        "DOMAIN-SUFFIX,hdsky.me",
        "DOMAIN-SUFFIX,audiences.me",
        "DOMAIN-SUFFIX,rainbowisland.co",
        "DOMAIN-KEYWORD,tracker",
        "DOMAIN-KEYWORD,announce",
    ]
    for r in fetch_lines(UPSTREAM["pt"]) + fetch_lines(UPSTREAM["chinamax"]):
        _, val = extract_target(r)
        if val in FORCE_PROXY_DOMAINS:
            continue
        direct_rules.append(r)
    write_list(RULES_DIR / "ChinaMax.list", "ChinaMax & PT Direct (Cleaned)", direct_rules)


if __name__ == "__main__":
    build_all()
