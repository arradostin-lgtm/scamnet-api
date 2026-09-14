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
    timeout: float = 20.0,
) -> dict:
    """
    Main entry point. Search the internet for scam mentions and social profiles.

    Returns:
        {
            "social": {"VK": "url", "Instagram": "url", ...},
            "mentions": [
                {"source": "banki.ru", "text": "...", "url": "...", "severity": "high"},
                ...
            ],
            "search_urls": {"google": "...", "vk": "..."},
            "query_names": ["name", "alias", ...],
        }
    """
    names = [name] + [a for a in (aliases or []) if a and a != name]

    social_task = asyncio.create_task(_find_social_profiles(names[0], timeout=timeout))
    mentions_task = asyncio.create_task(_find_scam_mentions(names, nationality, timeout=timeout))

    try:
        social, mentions = await asyncio.gather(social_task, mentions_task)
    except Exception:
        social, mentions = {}, []

    return {
        "social": social,
        "mentions": mentions,
        "search_urls": _build_manual_search_urls(names[0]),
        "query_names": names,
    }


async def _find_social_profiles(name: str, timeout: float = 15.0) -> dict:
    """Search social media profiles via DuckDuckGo or Google CSE."""
    social = {}

    for plat in SOCIAL_PLATFORMS:
        url = await _search_one_platform(name, plat, timeout=min(8, timeout))
        if url:
            social[plat["name"]] = url

    return social


async def _search_one_platform(name: str, plat: dict, timeout: float = 8.0) -> Optional[str]:
    """Search for one social platform profile."""
    query = f'"{name}" site:{plat["domain"]}'
    results = await _ddg_search(query, max_results=5, timeout=timeout)

    for r in results:
        url = r.get("href", "") or r.get("url", "")
        if re.search(plat["pattern"], url, re.I):
            # Exclude common non-profile pages
            if any(skip in url for skip in ["/search", "/hashtag", "/explore", "/reel", "/p/"]):
                continue
            return url
    return None


async def _find_scam_mentions(
    names: list,
    nationality: Optional[str],
    timeout: float = 20.0,
) -> list:
    """Search scam forums and review sites for mentions."""
    mentions = []

    # Site-specific searches
    site_tasks = []
    for site in SCAM_SITES:
        for name in names[:2]:  # limit to first 2 names/aliases
            q = site["query"].replace("{name}", name)
            site_tasks.append(_search_site_mention(q, site["name"], site["severity"], timeout=8.0))

    # General scam search (not site-restricted)
    for name in names[:2]:
        general_q = f'"{name}" мошенник обманул жертвы скам fraud'
        site_tasks.append(_search_site_mention(general_q, "Веб-поиск", "medium", timeout=8.0, general=True))

    results = await asyncio.gather(*site_tasks, return_exceptions=True)

    seen_urls = set()
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

    # Sort: high severity first, then by source
    mentions.sort(key=lambda m: (0 if m["severity"] == "high" else 1 if m["severity"] == "medium" else 2))
    return mentions[:12]  # cap at 12


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


def _build_manual_search_urls(name: str) -> dict:
    q = name.replace(" ", "+")
    qe = name.replace(" ", "%20")
    return {
        "google":    f"https://www.google.com/search?q=%22{qe}%22+мошенник",
        "vk":        f"https://vk.com/search?c%5Bsection%5D=people&q={q}",
        "linkedin":  f"https://www.linkedin.com/search/results/people/?keywords={qe}",
        "instagram": f"https://www.instagram.com/explore/tags/{q}/",
        "banki":     f"https://www.banki.ru/services/search/?search={qe}",
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
