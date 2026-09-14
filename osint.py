"""
OSINT module — internet search for scam mentions and social profiles.

Primary: DuckDuckGo (free, no API key).
Optional: Google Custom Search (set GOOGLE_SEARCH_API_KEY + GOOGLE_SEARCH_CX in env).

Returns social profile links and structured scam mentions with source, text, url.
"""
import asyncio
import json
import os
import re
from typing import Optional

import httpx

GOOGLE_SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY", "")
GOOGLE_SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX", "")

# ── Scam forum / review sites to specifically search ──────────────────────────
SCAM_SITES = [
    {"name": "banki.ru",         "query": 'site:banki.ru "{name}" мошенник',           "severity": "high"},
    {"name": "Отзовик",          "query": 'site:otzovik.com "{name}" мошенник обман',   "severity": "high"},
    {"name": "Пикабу",           "query": 'site:pikabu.ru "{name}" мошенник обманул',   "severity": "high"},
    {"name": "iRecommend",       "query": 'site:irecommend.ru "{name}" мошенник',       "severity": "medium"},
    {"name": "Отзыв.ру",        "query": 'site:otziv.ru "{name}" мошенник',            "severity": "medium"},
    {"name": "Судебные решения", "query": 'site:sudact.ru "{name}" мошенничество',      "severity": "high"},
    {"name": "ГАС Правосудие",  "query": 'site:kad.arbitr.ru "{name}"',               "severity": "high"},
    {"name": "RomanceScam",      "query": 'site:romancescam.com "{name}"',              "severity": "high"},
    {"name": "ScamAdviser",      "query": 'site:scamadviser.com "{name}"',              "severity": "medium"},
    {"name": "StopScam",         "query": 'site:stopscam.ru "{name}" мошенник',        "severity": "high"},
]

# ── Social media platforms ─────────────────────────────────────────────────────
SOCIAL_PLATFORMS = [
    {"name": "VK",            "domain": "vk.com",        "pattern": r'vk\.com/([\w\.]+)(?:\?|/|$)'},
    {"name": "Instagram",     "domain": "instagram.com",  "pattern": r'instagram\.com/([\w\.]+)(?:\?|/|$)'},
    {"name": "Telegram",      "domain": "t.me",           "pattern": r't\.me/([\w]+)'},
    {"name": "Facebook",      "domain": "facebook.com",   "pattern": r'facebook\.com/(?:people/[\w\.\-]+|[\w\.]+)'},
    {"name": "Twitter",       "domain": "x.com",          "pattern": r'(?:x|twitter)\.com/([\w]+)'},
    {"name": "Одноклассники", "domain": "ok.ru",          "pattern": r'ok\.ru/profile/\d+'},
    {"name": "TikTok",        "domain": "tiktok.com",     "pattern": r'tiktok\.com/@([\w\.]+)'},
    {"name": "YouTube",       "domain": "youtube.com",    "pattern": r'youtube\.com/(?:@|channel/|user/)([\w\.\-]+)'},
    {"name": "LinkedIn",      "domain": "linkedin.com",   "pattern": r'linkedin\.com/in/([\w\-]+)'},
]


async def search_person(
    name: str,
    aliases: Optional[list] = None,
    nationality: Optional[str] = None,
    country: Optional[str] = None,
    platform_met: Optional[str] = None,
    username: Optional[str] = None,
    company: Optional[str] = None,
    timeout: float = 20.0,
) -> dict:
    """
    Search the internet for scam mentions and social profiles.
    All available signals (name, country, platform, company, username) are
    combined into each query for compound matching — not searched separately.

    Returns:
        {
            "social": {"VK": "url", "LinkedIn": "url", ...},
            "mentions": [{"source": "...", "text": "...", "url": "...", "severity": "..."}, ...],
            "search_urls": {"google": "...", ...},
            "query_names": ["name", ...],
        }
    """
    names = [name] + [a for a in (aliases or []) if a and a != name]
    ctx = _build_context(
        country=country or nationality,
        platform_met=platform_met,
        company=company,
        username=username,
    )

    social_task = asyncio.create_task(
        _find_social_profiles(names, ctx, username=username, timeout=timeout)
    )
    mentions_task = asyncio.create_task(
        _find_scam_mentions(names, ctx, timeout=timeout)
    )

    try:
        social, mentions = await asyncio.gather(social_task, mentions_task)
    except Exception:
        social, mentions = {}, []

    return {
        "social": social,
        "mentions": mentions,
        "search_urls": _build_manual_search_urls(names[0], ctx),
        "query_names": names,
    }


def _build_context(
    country: Optional[str] = None,
    platform_met: Optional[str] = None,
    company: Optional[str] = None,
    username: Optional[str] = None,
) -> list[str]:
    """
    Build a list of context terms to append to search queries.
    Each term is added verbatim — keeps queries short but precise.
    """
    terms = []
    if country:
        terms.append(country.strip())
    if platform_met and platform_met.lower() not in ("другое", "не указано", ""):
        terms.append(platform_met.strip())
    if company:
        terms.append(company.strip())
    # username used separately — don't add @ noise into site: queries
    return terms


def _name_term(name: str) -> str:
    """
    Wrap name in quotes for search, unless it's very short (≤3 chars, e.g. Chinese surnames).
    Short names need no quotes — surrounding context does the narrowing.
    """
    if len(name.replace(" ", "")) <= 3:
        return name
    return f'"{name}"'


async def _find_social_profiles(
    names: list[str],
    ctx: list[str],
    username: Optional[str],
    timeout: float = 15.0,
) -> dict:
    """
    Search social media profiles. For each platform, build a compound query:
      {name} {country} {platform_met} site:{domain}
    Also run a username-based search if a handle was provided.
    """
    social: dict = {}
    plat_timeout = min(9, timeout)
    tasks = []

    for plat in SOCIAL_PLATFORMS:
        # Primary: name + context combined
        for name in names[:2]:
            tasks.append((plat, name, _search_one_platform(name, plat, ctx, timeout=plat_timeout)))
        # Secondary: username search if provided
        if username:
            tasks.append((plat, username, _search_one_platform(
                username, plat, [], timeout=plat_timeout, is_username=True
            )))

    results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)

    for (plat, _, __), url in zip(tasks, results):
        if isinstance(url, Exception) or not url:
            continue
        if plat["name"] not in social:
            social[plat["name"]] = url

    return social


async def _search_one_platform(
    name: str,
    plat: dict,
    ctx: list[str],
    timeout: float = 9.0,
    is_username: bool = False,
) -> Optional[str]:
    """Build and run one compound platform search query."""
    name_q = _name_term(name) if not is_username else (
        f'"{name}"' if not name.startswith("@") else f'"{name[1:]}"'
    )

    site_path = "linkedin.com/in" if plat["name"] == "LinkedIn" else plat["domain"]

    # Combine: name + context terms + site restriction
    parts = [name_q] + ctx + [f"site:{site_path}"]
    query = " ".join(parts)

    results = await _ddg_search(query, max_results=5, timeout=timeout)

    for r in results:
        url = r.get("href", "") or r.get("url", "")
        if re.search(plat["pattern"], url, re.I):
            if any(skip in url for skip in ["/search", "/hashtag", "/explore", "/reel", "/p/"]):
                continue
            return url
    return None


async def _find_scam_mentions(
    names: list[str],
    ctx: list[str],
    timeout: float = 20.0,
) -> list:
    """
    Search scam forums and general web for fraud mentions.
    Context terms (country, platform, company) are appended to every query.
    """
    ctx_str = " ".join(ctx)  # e.g. "Узбекистан Telegram"

    site_tasks = []
    for site in SCAM_SITES:
        for name in names[:2]:
            base_q = site["query"].replace("{name}", name)
            # Append context if not already in query
            q = f"{base_q} {ctx_str}".strip() if ctx_str else base_q
            site_tasks.append(
                _search_site_mention(q, site["name"], site["severity"], timeout=8.0)
            )

    for name in names[:2]:
        name_q = _name_term(name)
        ctx_parts = [name_q] + ctx + ["мошенник", "обманул", "скам", "fraud"]
        general_q = " ".join(ctx_parts)
        site_tasks.append(
            _search_site_mention(general_q, "Веб-поиск", "medium", timeout=8.0, general=True)
        )

    results = await asyncio.gather(*site_tasks, return_exceptions=True)

    seen_urls: set = set()
    mentions = []
    for batch in results:
        if isinstance(batch, Exception) or not batch:
            continue
        for m in batch:
            url = m.get("url", "")
            if url and url in seen_urls:
                continue
            if url:
                seen_urls.add(url)
            mentions.append(m)

    mentions.sort(key=lambda m: (0 if m["severity"] == "high" else 1 if m["severity"] == "medium" else 2))
    return mentions[:12]


async def _search_site_mention(
    query: str,
    source_name: str,
    severity: str,
    timeout: float = 8.0,
    general: bool = False,
) -> list:
    """Run one DDG search and convert results to mention dicts."""
    results = await _ddg_search(query, max_results=3, timeout=timeout)
    mentions = []
    for r in results:
        url = r.get("href") or r.get("url") or ""
        title = r.get("title", "")
        body = r.get("body") or r.get("snippet") or ""

        # Skip irrelevant / low-signal results
        text = f"{title} {body}".lower()
        scam_kw = ["мошенник", "обман", "скам", "fraud", "scam", "victim", "жертва", "украл", "кинул"]
        if general and not any(kw in text for kw in scam_kw):
            continue

        display_source = source_name
        if general and url:
            # Extract domain as source name for general results
            m = re.search(r'https?://(?:www\.)?([\w\-]+\.\w+)', url)
            if m:
                display_source = m.group(1)

        snippet = body[:180].strip() if body else title[:180]
        if not snippet:
            continue

        mentions.append({
            "source": display_source,
            "text": snippet,
            "url": url if url.startswith("http") else None,
            "severity": severity,
        })
    return mentions


async def _ddg_search(query: str, max_results: int = 5, timeout: float = 10.0) -> list:
    """Search DuckDuckGo. Falls back to Google CSE if API key configured."""

    # Try Google CSE first if configured
    if GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_CX:
        try:
            return await _google_cse_search(query, max_results, timeout)
        except Exception:
            pass

    # DuckDuckGo via library
    try:
        from duckduckgo_search import AsyncDDGS
        async with AsyncDDGS() as ddgs:
            results = await asyncio.wait_for(
                ddgs.atext(query, max_results=max_results, region="ru-ru"),
                timeout=timeout,
            )
            return list(results) if results else []
    except asyncio.TimeoutError:
        return []
    except Exception:
        pass

    # Last resort: DDG Lite via raw HTTP
    try:
        return await _ddg_lite_search(query, max_results, timeout)
    except Exception:
        return []


async def _google_cse_search(query: str, max_results: int, timeout: float) -> list:
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": GOOGLE_SEARCH_API_KEY, "cx": GOOGLE_SEARCH_CX, "q": query, "num": max_results},
        )
        data = r.json()
        return [
            {"href": item.get("link"), "title": item.get("title"), "body": item.get("snippet")}
            for item in data.get("items", [])
        ]


async def _ddg_lite_search(query: str, max_results: int, timeout: float) -> list:
    """Fallback: DDG HTML endpoint (no JS)."""
    import urllib.parse
    url = "https://html.duckduckgo.com/html/"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Scamnet/1.0; +https://scamnet.uz)",
        "Accept-Language": "ru,en;q=0.9",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(url, data={"q": query, "kl": "ru-ru"}, headers=headers)

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    for a in soup.select("a.result__a")[:max_results]:
        href = a.get("href", "")
        title = a.get_text(strip=True)
        snippet_el = a.find_next("a", class_="result__snippet")
        snippet = snippet_el.get_text(strip=True) if snippet_el else ""
        if href:
            results.append({"href": href, "title": title, "body": snippet})
    return results


def _build_manual_search_urls(name: str, ctx: Optional[list] = None) -> dict:
    import urllib.parse
    ctx_str = " ".join(ctx or [])
    combined = f"{name} {ctx_str}".strip()
    q = urllib.parse.quote_plus(combined)
    qe = urllib.parse.quote(combined)
    name_q = urllib.parse.quote_plus(name)
    return {
        "google":    f"https://www.google.com/search?q=%22{urllib.parse.quote(name)}%22+{urllib.parse.quote_plus(ctx_str)}+мошенник",
        "vk":        f"https://vk.com/search?c%5Bsection%5D=people&q={name_q}",
        "linkedin":  f"https://www.linkedin.com/search/results/people/?keywords={q}",
        "instagram": f"https://www.instagram.com/explore/tags/{name_q}/",
        "banki":     f"https://www.banki.ru/services/search/?search={name_q}",
    }


# ── Reverse image search ───────────────────────────────────────────────────────

REVERSE_SEARCH_LINKS = {
    "Yandex Картинки": "https://yandex.ru/images/",
    "Google Lens":     "https://lens.google.com/",
    "TinEye":          "https://tineye.com/",
    "PimEyes":         "https://pimeyes.com/en",
}


async def reverse_image_search(image_bytes: bytes, timeout: float = 20.0) -> dict:
    """
    Reverse image search: POST photo to Yandex Images, extract social links
    and sites where the face was found.

    Returns:
        {
            "social":    {"VK": "url", ...},
            "found_on":  [{"url": "...", "title": "...", "severity": "medium"}],
            "entities":  ["Name extracted from Yandex"],
        }
    """
    try:
        return await _yandex_reverse_search(image_bytes, timeout)
    except asyncio.TimeoutError:
        return {"social": {}, "found_on": [], "entities": []}
    except Exception as e:
        print(f"[osint] yandex reverse search: {e}")
        return {"social": {}, "found_on": [], "entities": []}


# Domains to skip in reverse search results (Yandex's own services and noise)
_SKIP_DOMAINS = {
    "ya.ru", "yandex.ru", "yandex.com", "yandex.by", "yandex.kz", "yandex.ua",
    "google.com", "google.ru", "bing.com", "mail.ru", "rambler.ru",
}


def _is_noise_url(url: str) -> bool:
    m = re.search(r'https?://(?:www\.)?([\w\-\.]+)', url)
    if not m:
        return True
    domain = m.group(1).lower()
    return any(domain == skip or domain.endswith("." + skip) for skip in _SKIP_DOMAINS)


async def _yandex_reverse_search(image_bytes: bytes, timeout: float = 20.0) -> dict:
    import io
    from bs4 import BeautifulSoup

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
        "Referer": "https://yandex.ru/images/",
    }

    async with httpx.AsyncClient(
        headers=headers, follow_redirects=True, timeout=timeout
    ) as client:
        files = {"upfile": ("photo.jpg", io.BytesIO(image_bytes), "image/jpeg")}
        r = await client.post(
            "https://yandex.ru/images/search",
            data={"rpt": "imageview", "cbir_page": "sites"},
            files=files,
        )

    if r.status_code not in (200, 301, 302):
        return {"social": {}, "found_on": [], "entities": []}

    soup = BeautifulSoup(r.text, "html.parser")

    social: dict = {}
    found_on: list = []
    entities: list = []

    def _norm(href: str) -> str:
        if href.startswith("//"):
            return "https:" + href
        return href if href.startswith("http") else ""

    # 1. Targeted Yandex "Sites where image appears" blocks
    for sel in [
        ".CbirSites__item",
        ".cbir-section__sites-item",
        "[class*='CbirSite']",
        ".serp-item",
    ]:
        for item in soup.select(sel):
            a = item.select_one("a[href]")
            if not a:
                continue
            href = _norm(a.get("href", ""))
            if not href or _is_noise_url(href):
                continue
            title = item.get_text(" ", strip=True)[:200]
            _collect(href, title, social, found_on)
        if found_on:
            break

    # 2. Fallback: scan all external links, skipping Yandex/noise
    if not found_on:
        seen: set = set()
        for a in soup.select("a[href]"):
            href = _norm(a.get("href", ""))
            if not href or href in seen or _is_noise_url(href):
                continue
            if any(x in href for x in ["javascript:", "mailto:", "#"]):
                continue
            seen.add(href)
            title = a.get_text(" ", strip=True)[:200]
            if not title or len(title) < 3:
                continue
            _collect(href, title, social, found_on)
            if len(found_on) >= 10:
                break

    # 3. Named entity / celebrity recognition by Yandex
    for sel in [".CbirCelebrity__title", "[class*='celebrity']", "[class*='Celebrity']"]:
        for el in soup.select(sel):
            t = el.get_text(strip=True)
            if t and len(t) > 2:
                entities.append(t)

    return {"social": social, "found_on": found_on[:10], "entities": entities[:3]}


def _collect(href: str, title: str, social: dict, found_on: list) -> None:
    """Classify one URL: put into social dict if it's a profile, else found_on list."""
    for plat in SOCIAL_PLATFORMS:
        if plat["domain"] in href:
            m = re.search(plat["pattern"], href, re.I)
            if m and not any(s in href for s in ["/search", "/hashtag", "/explore", "/reel", "/p/"]):
                if plat["name"] not in social:
                    social[plat["name"]] = href
            return
    if title:
        found_on.append({"url": href, "title": title, "severity": "medium"})


def _domain_label(url: str) -> str:
    m = re.search(r'https?://(?:www\.)?([\w\-]+\.[\w\-]+)', url)
    return m.group(1) if m else url[:40]


def format_for_response(osint: dict) -> dict:
    """Convert search_person() output to API response fields."""
    return {
        "osint_social":   osint.get("social", {}),
        "osint_mentions": osint.get("mentions", []),
        "osint_search_urls": osint.get("search_urls", {}),
    }
