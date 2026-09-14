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
# Vision API can use its own key (if restricted) or fall back to search key
GOOGLE_VISION_API_KEY = os.getenv("GOOGLE_VISION_API_KEY", "") or GOOGLE_SEARCH_API_KEY
BING_SEARCH_API_KEY = os.getenv("BING_SEARCH_API_KEY", "")
SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")
VK_SERVICE_TOKEN = os.getenv("VK_SERVICE_TOKEN", "")        # vk.com/dev → Standalone app → Service token
OPENSANCTIONS_API_KEY = os.getenv("OPENSANCTIONS_API_KEY", "")  # optional, free tier works without key
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")                    # haveibeenpwned.com, $3.50/month
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")        # @BotFather → /newbot → token
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")          # numverify.com, free 250 req/month
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "")          # leakcheck.io, 100 free/month
IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")                    # ipqualityscore.com, 200 free/month
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")               # hunter.io, 25 free/month
EMAILREP_API_KEY = os.getenv("EMAILREP_API_KEY", "")           # emailrep.io, 1000 free/day with key, 100/day without

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
    email: Optional[str] = None,
    phone: Optional[str] = None,
    timeout: float = 20.0,
) -> dict:
    """
    Search the internet for scam mentions and social profiles.
    All available signals (name, country, platform, company, username, email) are
    combined into each query for compound matching — not searched separately.

    Returns:
        {
            "social": {"VK": "url", "LinkedIn": "url", ...},
            "mentions": [{"source": "...", "text": "...", "url": "...", "severity": "..."}, ...],
            "search_urls": {"google": "...", ...},
            "query_names": ["name", ...],
            "sanctions": [{"name": "...", "datasets": [...], "score": 0.9}, ...],
            "email_breaches": ["Adobe", "LinkedIn", ...],
            "telegram": {"exists": True, "username": "...", "url": "..."} or None,
            "phone_info": {"valid": True, "country": "...", "line_type": "voip", ...} or None,
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
        _find_social_profiles(names, ctx, username=username, timeout=timeout,
                              prefer_country=country or nationality,
                              prefer_platform=platform_met)
    )
    mentions_task = asyncio.create_task(
        _find_scam_mentions(names, ctx, timeout=timeout)
    )
    sanctions_task = asyncio.create_task(
        _opensanctions_search(name, country=country or nationality, timeout=10.0)
    )

    async def _empty_list() -> list:
        return []

    async def _empty_none() -> None:
        return None

    hibp_task = asyncio.create_task(
        _hibp_check(email, timeout=8.0) if email else _empty_list()
    )
    telegram_task = asyncio.create_task(
        _telegram_lookup(username, timeout=8.0) if username else _empty_none()
    )
    phone_task = asyncio.create_task(
        _numverify_lookup(phone, timeout=8.0) if phone else _empty_none()
    )
    leakcheck_task = asyncio.create_task(
        _leakcheck(email, timeout=8.0) if email else _empty_list()
    )
    ipqs_email_task = asyncio.create_task(
        _ipqs_email(email, timeout=8.0) if email else _empty_none()
    )
    ipqs_phone_task = asyncio.create_task(
        _ipqs_phone(phone, timeout=8.0) if phone else _empty_none()
    )
    hunter_task = asyncio.create_task(
        _hunter_email(email, timeout=8.0) if email else _empty_none()
    )
    emailrep_task = asyncio.create_task(
        _emailrep(email, timeout=8.0) if email else _empty_none()
    )

    try:
        (
            social, mentions, sanctions,
            email_breaches, telegram, phone_info,
            leakcheck, ipqs_email, ipqs_phone, hunter_email, emailrep,
        ) = await asyncio.gather(
            social_task, mentions_task, sanctions_task,
            hibp_task, telegram_task, phone_task,
            leakcheck_task, ipqs_email_task, ipqs_phone_task, hunter_task, emailrep_task,
            return_exceptions=True,
        )
        if isinstance(social, Exception):        social = {}
        if isinstance(mentions, Exception):      mentions = []
        if isinstance(sanctions, Exception):     sanctions = []
        if isinstance(email_breaches, Exception): email_breaches = []
        if isinstance(telegram, Exception):      telegram = None
        if isinstance(phone_info, Exception):    phone_info = None
        if isinstance(leakcheck, Exception):     leakcheck = []
        if isinstance(ipqs_email, Exception):    ipqs_email = None
        if isinstance(ipqs_phone, Exception):    ipqs_phone = None
        if isinstance(hunter_email, Exception):  hunter_email = None
        if isinstance(emailrep, Exception):      emailrep = None
    except Exception:
        social, mentions, sanctions = {}, [], []
        email_breaches, telegram, phone_info = [], None, None
        leakcheck, ipqs_email, ipqs_phone, hunter_email, emailrep = [], None, None, None, None

    # If Telegram confirmed the account exists — add to social dict
    if telegram and telegram.get("exists") and telegram.get("url"):
        social.setdefault("Telegram", telegram["url"])

    return {
        "social":        social,
        "mentions":      mentions,
        "search_urls":   _build_manual_search_urls(names[0], ctx),
        "query_names":   names,
        "sanctions":     sanctions,
        "email_breaches": email_breaches,
        "telegram":      telegram,
        "phone_info":    phone_info,
        "leakcheck":     leakcheck,
        "ipqs_email":    ipqs_email,
        "ipqs_phone":    ipqs_phone,
        "hunter_email":  hunter_email,
        "emailrep":      emailrep,
    }


def _build_context(
    country: Optional[str] = None,
    platform_met: Optional[str] = None,
    company: Optional[str] = None,
    username: Optional[str] = None,
) -> list:
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
    names: list,
    ctx: list,
    username: Optional[str],
    timeout: float = 15.0,
    prefer_country: Optional[str] = None,
    prefer_platform: Optional[str] = None,
) -> dict:
    """
    Search social media profiles.

    IMPORTANT: DuckDuckGo's site: operator is broken — it returns garbage.
    Instead we use the domain as a bare keyword (e.g. "linkedin.com/in").
    Context terms (country, platform_met) are NOT added here — they break DDG.
    Country is used AFTER results are fetched to pick the best matching profile.
    When prefer_platform is set (e.g. "Instagram"), we search that platform first
    and with more results.
    VK API search runs in parallel if VK_SERVICE_TOKEN is configured.
    """
    plat_timeout = min(9, timeout)
    tasks = []

    # Sort platforms: prefer_platform goes first
    platform_order = sorted(
        SOCIAL_PLATFORMS,
        key=lambda p: 0 if prefer_platform and prefer_platform.lower() in p["name"].lower() else 1
    )

    for plat in platform_order:
        extra = prefer_platform and prefer_platform.lower() in plat["name"].lower()
        for name in names[:2]:
            tasks.append((plat, _search_one_platform(
                name, plat, timeout=plat_timeout, prefer_country=prefer_country,
                max_results=15 if extra else 10,
            )))
        if username:
            tasks.append((plat, _search_one_platform(
                username, plat, timeout=plat_timeout, is_username=True, prefer_country=prefer_country,
                max_results=15 if extra else 10,
            )))

    # VK API search runs in parallel (more accurate than text search)
    vk_task = None
    if VK_SERVICE_TOKEN:
        vk_task = asyncio.create_task(
            _vk_api_search(names[0], country=prefer_country, timeout=plat_timeout)
        )

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

    social: dict = {}
    for (plat, _), url in zip(tasks, results):
        if isinstance(url, Exception) or not url:
            continue
        if plat["name"] not in social:
            social[plat["name"]] = url

    # VK API result overrides text-search VK result (more accurate)
    if vk_task is not None:
        try:
            vk_result = await asyncio.wait_for(vk_task, timeout=plat_timeout)
            if vk_result:
                social["VK"] = vk_result
                print(f"[osint] VK API found: {vk_result}")
        except Exception as e:
            print(f"[osint] VK API error: {e}")

    return social


def _normalise_linkedin(url: str) -> str:
    """Convert uz.linkedin.com/in/X or ru.linkedin.com/in/X → linkedin.com/in/X"""
    return re.sub(r'https?://[a-z]{2}\.linkedin\.com/', 'https://www.linkedin.com/', url)


async def _search_one_platform(
    name: str,
    plat: dict,
    timeout: float = 9.0,
    is_username: bool = False,
    prefer_country: Optional[str] = None,
    max_results: int = 10,
) -> Optional[str]:
    """
    Search for one social platform profile.
    Uses domain as a keyword (NOT site: operator — broken in DDG).
    Query: {name} {domain_keyword}
    e.g.  Поздняков Иван linkedin.com/in

    When prefer_country is given, scores country-matching subdomain results higher
    (e.g. uz.linkedin.com wins over ru.linkedin.com when country=Uzbekistan/Узбекистан).
    """
    if is_username:
        clean = name.lstrip("@")
        name_q = f'"{clean}"' if len(clean) > 3 else clean
    else:
        name_q = _name_term(name)

    # Use domain path as keyword — LinkedIn needs /in/ to avoid company pages
    domain_kw = "linkedin.com/in" if plat["name"] == "LinkedIn" else plat["domain"]
    query = f"{name_q} {domain_kw}"

    results = await _ddg_search(query, max_results=max_results, timeout=timeout)

    candidates = []
    for r in results:
        url = r.get("href", "") or r.get("url", "")
        if not re.search(plat["pattern"], url, re.I):
            continue
        if any(skip in url for skip in ["/search", "/hashtag", "/explore", "/reel", "/p/"]):
            continue
        candidates.append(url)

    if not candidates:
        return None

    # If country hint provided, prefer profile from matching country subdomain
    if prefer_country and plat["name"] == "LinkedIn":
        best = _pick_by_country(candidates, prefer_country)
        if best:
            return _normalise_linkedin(best)

    return _normalise_linkedin(candidates[0]) if plat["name"] == "LinkedIn" else candidates[0]


# Country name → LinkedIn subdomain prefix (covers Cyrillic and Latin variants)
_COUNTRY_TO_SUBDOMAIN = {
    "узбекистан": "uz", "uzbekistan": "uz",
    "россия": "ru", "russia": "ru",
    "казахстан": "kz", "kazakhstan": "kz",
    "беларусь": "by", "belarus": "by",
    "украина": "ua", "ukraine": "ua",
    "германия": "de", "germany": "de",
    "сша": "us", "usa": "us", "united states": "us",
    "великобритания": "gb", "uk": "gb",
    "турция": "tr", "turkey": "tr",
    "китай": "cn", "china": "cn",
    "индия": "in", "india": "in",
    "франция": "fr", "france": "fr",
    "польша": "pl", "poland": "pl",
    "азербайджан": "az", "azerbaijan": "az",
    "грузия": "ge", "georgia": "ge",
    "армения": "am", "armenia": "am",
    "кыргызстан": "kg", "kyrgyzstan": "kg",
    "таджикистан": "tj", "tajikistan": "tj",
}


def _pick_by_country(urls: list, country: str) -> Optional[str]:
    """Return the first URL whose subdomain matches the country hint, or None."""
    code = _COUNTRY_TO_SUBDOMAIN.get(country.lower().strip())
    if not code:
        return None
    prefix = f"{code}.linkedin.com"
    for url in urls:
        if prefix in url.lower():
            return url
    return None


async def _vk_api_search(
    name: str,
    country: Optional[str] = None,
    timeout: float = 9.0,
) -> Optional[str]:
    """
    VK API users.search — returns profile URL of the best matching person.
    Requires VK_SERVICE_TOKEN (vk.com/dev → Standalone app → Service token).
    Filters by country when provided. Prefers profiles that have a photo.
    """
    if not VK_SERVICE_TOKEN:
        return None

    # Map country name (Russian/English) to VK country_id
    # VK country IDs: Russia=1, Ukraine=2, Belarus=3, Kazakhstan=4,
    # Uzbekistan=238, Germany=80, USA=203, Turkey=183, China=44, ...
    _COUNTRY_TO_VK_ID = {
        "россия": 1, "russia": 1,
        "украина": 2, "ukraine": 2,
        "беларусь": 3, "belarus": 3,
        "казахстан": 4, "kazakhstan": 4,
        "азербайджан": 6, "azerbaijan": 6,
        "грузия": 7, "georgia": 7,
        "армения": 8, "armenia": 8,
        "кыргызстан": 10, "kyrgyzstan": 10,
        "таджикистан": 26, "tajikistan": 26,
        "узбекистан": 238, "uzbekistan": 238,
        "германия": 80, "germany": 80,
        "франция": 73, "france": 73,
        "великобритания": 67, "uk": 67,
        "сша": 203, "usa": 203, "united states": 203,
        "турция": 183, "turkey": 183,
        "китай": 44, "china": 44,
        "польша": 146, "poland": 146,
    }

    params: dict = {
        "q": name,
        "count": 10,
        "fields": "photo_max,city,country,screen_name",
        "access_token": VK_SERVICE_TOKEN,
        "v": "5.199",
    }

    if country:
        vk_country_id = _COUNTRY_TO_VK_ID.get(country.lower().strip())
        if vk_country_id:
            params["country"] = vk_country_id

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                "https://api.vk.com/method/users.search",
                params=params,
            )
        data = r.json()

        if "error" in data:
            print(f"[osint] VK API error: {data['error'].get('error_msg', data['error'])}")
            return None

        items = data.get("response", {}).get("items", [])
        if not items:
            return None

        # Prefer users with a profile photo
        with_photo = [u for u in items if u.get("photo_max") and "camera" not in u.get("photo_max", "")]
        best = with_photo[0] if with_photo else items[0]

        screen_name = best.get("screen_name") or f"id{best['id']}"
        return f"https://vk.com/{screen_name}"

    except Exception as e:
        print(f"[osint] VK API exception: {e}")
        return None


async def _find_scam_mentions(
    names: list,
    ctx: list,
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


async def _ddg_search(query: str, max_results: int = 7, timeout: float = 10.0) -> list:
    """Search the web. Uses Google CSE if configured, falls back to DuckDuckGo."""

    # Google CSE — primary (configured with social network sites)
    if GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_CX:
        try:
            results = await _google_cse_search(query, max_results, timeout)
            if results:
                return results
        except Exception as e:
            print(f"[search] Google CSE error: {e}")

    # DuckDuckGo fallback — try new package name first, then old
    import concurrent.futures
    loop = asyncio.get_event_loop()

    def _sync_search():
        # Try new package name (ddgs)
        try:
            from ddgs import DDGS
            with DDGS() as d:
                return list(d.text(query, max_results=max_results, region="ru-ru") or [])
        except ImportError:
            pass
        # Fall back to old package name (duckduckgo_search)
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from duckduckgo_search import DDGS
            with DDGS() as d:
                return list(d.text(query, max_results=max_results, region="ru-ru") or [])
        except Exception:
            return []

    _executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        results = await asyncio.wait_for(
            loop.run_in_executor(_executor, _sync_search),
            timeout=timeout,
        )
        return results if results else []
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
    Reverse image search: find social profiles and web pages where this face appears.
    Tries Bing Visual Search first (if API key set), then falls back to Yandex.

    Returns:
        {
            "social":    {"VK": "url", ...},
            "found_on":  [{"url": "...", "title": "...", "severity": "medium"}],
            "entities":  ["Name recognised from photo"],
        }
    """
    # Google Cloud Vision — web detection, accepts base64 directly
    if GOOGLE_VISION_API_KEY:
        try:
            result = await _google_vision_web_detect(image_bytes, timeout)
            if result.get("social") or result.get("found_on") or result.get("entities"):
                print(f"[osint] google vision: found {len(result.get('found_on',[]))} pages, entities={result.get('entities')}")
                return result
        except Exception as e:
            print(f"[osint] google vision failed: {e}")

    # SerpApi Google Lens fallback (needs image URL, uploads to imgbb first)
    if SERPAPI_KEY:
        try:
            result = await _serpapi_reverse_search(image_bytes, timeout)
            if result.get("social") or result.get("found_on") or result.get("entities"):
                print(f"[osint] serpapi lens: found {len(result.get('found_on',[]))} pages, entities={result.get('entities')}")
                return result
        except Exception as e:
            print(f"[osint] serpapi failed: {e}")

    # Bing Visual Search fallback
    if BING_SEARCH_API_KEY:
        try:
            result = await _bing_visual_search(image_bytes, timeout)
            if result.get("social") or result.get("found_on") or result.get("entities"):
                print(f"[osint] bing visual search: found {len(result.get('found_on',[]))} pages, entities={result.get('entities')}")
                return result
        except Exception as e:
            print(f"[osint] bing visual search failed: {e}")

    # Yandex fallback
    try:
        return await _yandex_reverse_search(image_bytes, timeout)
    except asyncio.TimeoutError:
        return {"social": {}, "found_on": [], "entities": []}
    except Exception as e:
        print(f"[osint] yandex reverse search: {e}")
        return {"social": {}, "found_on": [], "entities": []}


async def _google_vision_web_detect(image_bytes: bytes, timeout: float = 20.0) -> dict:
    """
    Google Cloud Vision API — WEB_DETECTION feature.
    Finds pages where this face/image appears + extracts entity names.
    Accepts base64 directly — no image hosting needed.
    Requires Cloud Vision API enabled in Google Cloud + GOOGLE_SEARCH_API_KEY.
    """
    import base64

    b64 = base64.b64encode(image_bytes).decode()

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            "https://vision.googleapis.com/v1/images:annotate",
            params={"key": GOOGLE_VISION_API_KEY},
            json={"requests": [{
                "image": {"content": b64},
                "features": [{"type": "WEB_DETECTION", "maxResults": 10}],
            }]},
        )

    if r.status_code != 200:
        raise ValueError(f"Google Vision HTTP {r.status_code}: {r.text[:300]}")

    web = r.json().get("responses", [{}])[0].get("webDetection", {})

    social: dict = {}
    found_on: list = []
    entities: list = []

    # Entity names — person/celebrity recognition
    for ent in web.get("webEntities", []):
        desc = ent.get("description", "")
        score = ent.get("score", 0)
        if desc and score > 0.5 and desc not in entities:
            entities.append(desc)

    # Pages where this exact or similar image appears
    for page in web.get("pagesWithMatchingImages", []):
        url = page.get("url", "")
        title = page.get("pageTitle", "")
        if url and not _is_noise_url(url):
            _collect(url, title, social, found_on)

    # Also check visually similar images for social profile photos
    for img in web.get("visuallySimilarImages", []):
        url = img.get("url", "")
        if url and not _is_noise_url(url):
            for plat in SOCIAL_PLATFORMS:
                if plat["domain"] in url:
                    m = re.search(plat["pattern"], url, re.I)
                    if m and plat["name"] not in social:
                        social[plat["name"]] = url
                    break

    return {"social": social, "found_on": found_on[:10], "entities": entities[:5]}


async def _serpapi_reverse_search(image_bytes: bytes, timeout: float = 20.0) -> dict:
    """
    SerpApi Google Lens reverse image search.
    Uploads image to imgbb.com first to get a URL, then passes to SerpApi.
    Free tier: 100 searches/month. Requires SERPAPI_KEY.
    """
    import base64

    # Upload to imgbb to get a temporary URL
    b64 = base64.b64encode(image_bytes).decode()
    imgbb_key = os.getenv("IMGBB_API_KEY", "")

    image_url = None
    if imgbb_key:
        async with httpx.AsyncClient(timeout=15) as client:
            up = await client.post(
                "https://api.imgbb.com/1/upload",
                data={"key": imgbb_key, "image": b64, "expiration": "300"},
            )
            if up.status_code == 200:
                image_url = up.json().get("data", {}).get("url")

    if not image_url:
        raise ValueError("No image URL for SerpApi (IMGBB_API_KEY not set or upload failed)")

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(
            "https://serpapi.com/search",
            params={"engine": "google_lens", "url": image_url, "api_key": SERPAPI_KEY},
        )

    if r.status_code != 200:
        raise ValueError(f"SerpApi HTTP {r.status_code}: {r.text[:200]}")

    data = r.json()
    social: dict = {}
    found_on: list = []
    entities: list = []

    for item in data.get("visual_matches", []):
        url = item.get("link", "")
        title = item.get("title", "") or item.get("source", "")
        if url and not _is_noise_url(url):
            _collect(url, title, social, found_on)

    kg = data.get("knowledge_graph", {})
    if kg.get("title"):
        entities.append(kg["title"])

    for item in data.get("related_content", []):
        url = item.get("link", "")
        title = item.get("title", "")
        if url and not _is_noise_url(url):
            _collect(url, title, social, found_on)

    return {"social": social, "found_on": found_on[:10], "entities": entities[:3]}


async def _bing_visual_search(image_bytes: bytes, timeout: float = 20.0) -> dict:
    """
    Microsoft Bing Visual Search API.
    Finds pages where the image appears + entity recognition (person name).
    Free tier: 1 000 queries/month. Requires BING_SEARCH_API_KEY.
    """
    import io

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            "https://api.bing.microsoft.com/v7.0/images/visualsearch",
            headers={"Ocp-Apim-Subscription-Key": BING_SEARCH_API_KEY},
            files={"image": ("photo.jpg", io.BytesIO(image_bytes), "image/jpeg")},
        )

    if r.status_code != 200:
        raise ValueError(f"Bing Visual Search HTTP {r.status_code}: {r.text[:200]}")

    data = r.json()
    social: dict = {}
    found_on: list = []
    entities: list = []

    for tag in data.get("tags", []):
        for action in tag.get("actions", []):
            action_type = action.get("actionType", "")

            # Entity/celebrity recognition — extracts person's name
            if action_type == "Entity":
                display_name = action.get("displayName", "") or action.get("name", "")
                if display_name and display_name not in entities:
                    entities.append(display_name)

            # Pages where the exact image appears
            if action_type in ("PagesIncluding", "VisualSearch"):
                for item in action.get("data", {}).get("value", []):
                    url = item.get("hostPageUrl", "")
                    title = item.get("name", "") or item.get("hostPageDisplayUrl", "")
                    if url and not _is_noise_url(url):
                        _collect(url, title, social, found_on)

    return {"social": social, "found_on": found_on[:10], "entities": entities[:3]}


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


async def _telegram_lookup(username: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    Check if a Telegram username exists via Bot API getChat.
    Returns profile info if the account is public, None if private/not found.
    Requires TELEGRAM_BOT_TOKEN (@BotFather → /newbot).
    """
    if not TELEGRAM_BOT_TOKEN or not username:
        return None

    clean = username.lstrip("@").strip()
    if len(clean) < 3:
        return None

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat",
                params={"chat_id": f"@{clean}"},
            )
        data = r.json()
        if not data.get("ok"):
            print(f"[osint] Telegram @{clean}: not found or private")
            return {"exists": False, "username": clean}

        res = data.get("result", {})
        info = {
            "exists": True,
            "username": res.get("username", clean),
            "first_name": res.get("first_name"),
            "last_name": res.get("last_name"),
            "type": res.get("type"),      # "private" | "group" | "channel"
            "url": f"https://t.me/{clean}",
        }
        print(f"[osint] Telegram @{clean}: found ({res.get('type')})")
        return info
    except Exception as e:
        print(f"[osint] Telegram lookup error: {e}")
        return None


async def _numverify_lookup(phone: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    Validate phone number and get carrier/line type via NumVerify API.
    Free tier: 250 requests/month. Requires NUMVERIFY_API_KEY.
    VoIP numbers are a strong fraud signal.
    """
    if not NUMVERIFY_API_KEY or not phone:
        return None

    clean = re.sub(r"[^\d+]", "", phone)
    if len(clean) < 7:
        return None

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                "http://apilayer.net/api/validate",
                params={"access_key": NUMVERIFY_API_KEY, "number": clean, "format": 1},
            )
        data = r.json()

        if not data.get("valid"):
            return {"valid": False, "number": clean}

        line_type = data.get("line_type", "")
        risk_signals = []
        if line_type == "voip":
            risk_signals.append("VoIP номер — часто используется мошенниками")
        elif line_type == "toll_free":
            risk_signals.append("Бесплатный номер (800/888)")
        elif line_type == "premium_rate":
            risk_signals.append("Премиум-тариф")

        result = {
            "valid": True,
            "number": data.get("international_format", clean),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "carrier": data.get("carrier"),
            "line_type": line_type,
            "risk_signals": risk_signals,
        }
        print(f"[osint] NumVerify {clean}: {data.get('country_name')}, {line_type}, {data.get('carrier')}")
        return result
    except Exception as e:
        print(f"[osint] NumVerify error: {e}")
        return None


async def _opensanctions_search(
    name: str,
    country: Optional[str] = None,
    timeout: float = 10.0,
) -> list:
    """
    Search OpenSanctions API — 100+ sanctions lists (UN, OFAC, EU, Interpol, national).
    Free for non-commercial use. API key optional (higher rate limits with key).
    Returns list of matched entities with source datasets and score.
    """
    params: dict = {"q": name, "schema": "Person", "limit": 5}

    # Map country name to ISO-2 code for OpenSanctions filter
    _COUNTRY_ISO2 = {
        "россия": "RU", "russia": "RU",
        "украина": "UA", "ukraine": "UA",
        "узбекистан": "UZ", "uzbekistan": "UZ",
        "казахстан": "KZ", "kazakhstan": "KZ",
        "беларусь": "BY", "belarus": "BY",
        "азербайджан": "AZ", "azerbaijan": "AZ",
        "китай": "CN", "china": "CN",
        "германия": "DE", "germany": "DE",
        "сша": "US", "usa": "US", "united states": "US",
        "великобритания": "GB", "uk": "GB",
        "турция": "TR", "turkey": "TR",
    }
    if country:
        iso2 = _COUNTRY_ISO2.get(country.lower().strip())
        if iso2:
            params["countries"] = iso2

    headers: dict = {"Accept": "application/json"}
    if OPENSANCTIONS_API_KEY:
        headers["Authorization"] = f"ApiKey {OPENSANCTIONS_API_KEY}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                "https://api.opensanctions.org/search/entities",
                params=params,
                headers=headers,
            )
        if r.status_code == 403:
            print("[osint] OpenSanctions: API key required for this query")
            return []
        if r.status_code != 200:
            print(f"[osint] OpenSanctions HTTP {r.status_code}")
            return []

        data = r.json()
        results = []
        for item in data.get("results", []):
            score = item.get("score", 0)
            if score < 0.5:
                continue
            props = item.get("properties", {})
            results.append({
                "name": (props.get("name") or [name])[0],
                "score": round(score, 3),
                "datasets": item.get("datasets", [])[:4],
                "topics": item.get("topics", [])[:3],
                "birth_date": (props.get("birthDate") or [None])[0],
                "nationality": props.get("nationality", [])[:2],
            })
        if results:
            print(f"[osint] OpenSanctions: {len(results)} hits for '{name}'")
        return results
    except Exception as e:
        print(f"[osint] OpenSanctions error: {e}")
        return []


async def _hibp_check(email: Optional[str], timeout: float = 8.0) -> list:
    """
    Check email in HaveIBeenPwned — 700+ data breaches.
    Returns list of breach names where this email appeared.
    Requires HIBP_API_KEY ($3.50/month at haveibeenpwned.com).
    Without key: silently returns empty list.
    """
    if not email or not HIBP_API_KEY:
        return []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": HIBP_API_KEY,
                    "User-Agent": "Scamnet-OSINT/1.0",
                },
                params={"truncateResponse": "true"},
            )
        if r.status_code == 404:
            return []
        if r.status_code == 401:
            print("[osint] HIBP: invalid API key")
            return []
        if r.status_code == 429:
            print("[osint] HIBP: rate limited")
            return []
        if r.status_code != 200:
            print(f"[osint] HIBP HTTP {r.status_code}")
            return []

        breaches = r.json()
        names = [b.get("Name", "") for b in breaches if b.get("Name")]
        if names:
            print(f"[osint] HIBP: {len(names)} breaches for {email[:4]}***")
        return names
    except Exception as e:
        print(f"[osint] HIBP error: {e}")
        return []


async def _leakcheck(email: Optional[str], timeout: float = 8.0) -> list:
    """
    Leakcheck.io — check email in leaked databases.
    Free: 100 req/month with key. Public endpoint (no key) rate-limited.
    Returns list of {source, date, fields} dicts.
    """
    if not email:
        return []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if LEAKCHECK_API_KEY:
                r = await client.get(
                    f"https://leakcheck.io/api/v2/query/{email}",
                    headers={"X-API-Key": LEAKCHECK_API_KEY},
                )
            else:
                r = await client.get(
                    "https://leakcheck.io/api/public",
                    params={"check": email},
                )
        if r.status_code == 404:
            return []
        if r.status_code not in (200, 201):
            print(f"[osint] Leakcheck HTTP {r.status_code}")
            return []
        data = r.json()
        sources = data.get("sources") or data.get("result") or []
        results = []
        for s in sources:
            if isinstance(s, dict):
                results.append({
                    "source": s.get("name") or s.get("source", "?"),
                    "date": s.get("date") or s.get("last_breach"),
                    "fields": s.get("fields", []),
                })
            elif isinstance(s, str):
                results.append({"source": s, "date": None, "fields": []})
        if results:
            print(f"[osint] Leakcheck: {len(results)} sources for {email[:4]}***")
        return results
    except Exception as e:
        print(f"[osint] Leakcheck error: {e}")
        return []


async def _ipqs_email(email: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    IPQualityScore email fraud check.
    Returns fraud_score (0–100), disposable, valid, leaked, smtp_score.
    Free: 200 req/month at ipqualityscore.com.
    """
    if not email or not IPQS_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"https://ipqualityscore.com/api/json/email/{IPQS_API_KEY}/{email}",
                params={"fast": "true", "timeout": "5"},
            )
        if r.status_code != 200:
            print(f"[osint] IPQS email HTTP {r.status_code}")
            return None
        d = r.json()
        if not d.get("success"):
            print(f"[osint] IPQS email: {d.get('message')}")
            return None
        result = {
            "fraud_score":  d.get("fraud_score"),
            "valid":        d.get("valid"),
            "disposable":   d.get("disposable"),
            "leaked":       d.get("leaked"),
            "smtp_score":   d.get("smtp_score"),
            "overall_score": d.get("overall_score"),
            "domain_age_days": (d.get("domain_age") or {}).get("days"),
        }
        print(f"[osint] IPQS email fraud_score={result['fraud_score']} disposable={result['disposable']}")
        return result
    except Exception as e:
        print(f"[osint] IPQS email error: {e}")
        return None


async def _ipqs_phone(phone: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    IPQualityScore phone fraud check — runs alongside NumVerify, not replacing it.
    Returns fraud_score, line_type, carrier, risky, recent_abuse.
    Free: 200 req/month at ipqualityscore.com.
    """
    if not phone or not IPQS_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"https://ipqualityscore.com/api/json/phone/{IPQS_API_KEY}/{phone}",
                params={"fast": "true"},
            )
        if r.status_code != 200:
            print(f"[osint] IPQS phone HTTP {r.status_code}")
            return None
        d = r.json()
        if not d.get("success"):
            return None
        result = {
            "fraud_score":    d.get("fraud_score"),
            "valid":          d.get("valid"),
            "line_type":      d.get("line_type"),
            "carrier":        d.get("carrier"),
            "country":        d.get("country"),
            "risky":          d.get("risky"),
            "recent_abuse":   d.get("recent_abuse"),
            "do_not_call":    d.get("do_not_call"),
            "prepaid":        d.get("prepaid"),
        }
        print(f"[osint] IPQS phone fraud_score={result['fraud_score']} line_type={result['line_type']}")
        return result
    except Exception as e:
        print(f"[osint] IPQS phone error: {e}")
        return None


async def _hunter_email(email: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    Hunter.io — verify email and enrich with company/name data.
    Free: 25 req/month at hunter.io.
    Returns {deliverable, score, company, first_name, last_name, linkedin}.
    """
    if not email or not HUNTER_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": HUNTER_API_KEY},
            )
        if r.status_code != 200:
            print(f"[osint] Hunter HTTP {r.status_code}")
            return None
        d = r.json().get("data", {})
        result = {
            "status":      d.get("status"),        # valid/invalid/accept_all/unknown
            "score":       d.get("score"),          # deliverability 0–100
            "regexp":      d.get("regexp"),
            "gibberish":   d.get("gibberish"),
            "disposable":  d.get("disposable"),
            "webmail":     d.get("webmail"),
            "mx_records":  d.get("mx_records"),
            "smtp_server": d.get("smtp_server"),
        }
        print(f"[osint] Hunter email status={result['status']} score={result['score']}")
        return result
    except Exception as e:
        print(f"[osint] Hunter error: {e}")
        return None


async def _emailrep(email: Optional[str], timeout: float = 8.0) -> Optional[dict]:
    """
    Emailrep.io — email reputation and fraud signals.
    Free: 100 req/day without key, 1000/day with free key (emailrep.io).
    Returns reputation, suspicious flag, blacklisted, disposable, malicious_activity.
    """
    if not email:
        return None
    try:
        headers = {"User-Agent": "Scamnet-OSINT/1.0"}
        if EMAILREP_API_KEY:
            headers["Key"] = EMAILREP_API_KEY
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"https://emailrep.io/{email}",
                headers=headers,
            )
        if r.status_code == 400:
            print(f"[osint] Emailrep: invalid email {email[:4]}***")
            return None
        if r.status_code == 429:
            print("[osint] Emailrep: rate limited (100/day without key)")
            return None
        if r.status_code != 200:
            print(f"[osint] Emailrep HTTP {r.status_code}")
            return None
        d = r.json()
        details = d.get("details", {})
        result = {
            "reputation":              d.get("reputation"),           # high/medium/low/none
            "suspicious":              d.get("suspicious", False),
            "references":              d.get("references", 0),        # how many sources know this email
            "blacklisted":             details.get("blacklisted", False),
            "malicious_activity":      details.get("malicious_activity", False),
            "malicious_activity_recent": details.get("malicious_activity_recent", False),
            "disposable":              details.get("disposable", False),
            "free_provider":           details.get("free_provider", False),
            "days_since_domain_creation": details.get("days_since_domain_creation"),
            "spam":                    details.get("spam", False),
        }
        print(f"[osint] Emailrep: reputation={result['reputation']} suspicious={result['suspicious']} blacklisted={result['blacklisted']}")
        return result
    except Exception as e:
        print(f"[osint] Emailrep error: {e}")
        return None


def format_for_response(osint: dict) -> dict:
    """Convert search_person() output to API response fields."""
    return {
        "osint_social":   osint.get("social", {}),
        "osint_mentions": osint.get("mentions", []),
        "osint_search_urls": osint.get("search_urls", {}),
    }
