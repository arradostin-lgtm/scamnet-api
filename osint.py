"""
OSINT module — collect public social profiles for a known person.

Uses Google Custom Search JSON API (100 free queries/day).
Requires Railway env vars:
  GOOGLE_SEARCH_API_KEY  — Google API key with Custom Search enabled
  GOOGLE_SEARCH_CX       — Custom Search Engine ID (searches the whole web)

Fallback (no API key): returns direct search URLs for manual lookup.
"""
import asyncio
import json
import os
import re
from typing import Optional

import httpx

SEARCH_API_KEY = os.getenv("GOOGLE_SEARCH_API_KEY", "")
SEARCH_CX = os.getenv("GOOGLE_SEARCH_CX", "")

# Platform definitions: domain → url prefix for found profiles
PLATFORMS = {
    "linkedin":  {"domain": "linkedin.com/in",  "pattern": r'linkedin\.com/in/[\w\-%]+'},
    "instagram": {"domain": "instagram.com",     "pattern": r'instagram\.com/([\w\.]+)(?:/|\b)'},
    "facebook":  {"domain": "facebook.com",      "pattern": r'facebook\.com/(?:people/[\w\.\-]+|[\w\.]+)(?:/|\?|$)'},
    "vk":        {"domain": "vk.com",            "pattern": r'vk\.com/[\w\.]+'},
    "telegram":  {"domain": "t.me",              "pattern": r't\.me/[\w]+'},
    "twitter":   {"domain": "x.com OR twitter.com", "pattern": r'(?:x|twitter)\.com/[\w]+'},
}


async def enrich_profile(
    name: str,
    aliases: Optional[list] = None,
    nationality: Optional[str] = None,
) -> dict:
    """
    Search for social profiles of a person.
    Returns: {
        "linkedin": "url or None",
        "instagram": "url or None",
        "facebook": "url or None",
        "vk": "url or None",
        "telegram": "url or None",
        "twitter": "url or None",
        "search_urls": {...},   # fallback manual search links
        "raw_snippets": [...],  # text snippets found about the person
    }
    """
    all_names = [name] + (aliases or [])
    primary = all_names[0]

    results = {p: None for p in PLATFORMS}
    results["search_urls"] = _build_search_urls(primary)
    results["raw_snippets"] = []

    if not SEARCH_API_KEY or not SEARCH_CX:
        # No API key — return search URL links only
        return results

    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [
            _search_platform(client, primary, platform)
            for platform in PLATFORMS
        ]
        platform_results = await asyncio.gather(*tasks, return_exceptions=True)

    for platform, found in zip(PLATFORMS.keys(), platform_results):
        if isinstance(found, Exception):
            continue
        if found:
            results[platform] = found

    # Also do a general search for snippets about the person
    snippets = await _general_search(primary, nationality)
    results["raw_snippets"] = snippets

    return results


async def _search_platform(client: httpx.AsyncClient, name: str, platform: str) -> Optional[str]:
    """Search for a person's profile on one platform via Google CSE."""
    info = PLATFORMS[platform]
    query = f'"{name}" site:{info["domain"]}'

    try:
        r = await client.get(
            "https://www.googleapis.com/customsearch/v1",
            params={
                "key": SEARCH_API_KEY,
                "cx": SEARCH_CX,
                "q": query,
                "num": 3,
            },
        )
        data = r.json()
        items = data.get("items", [])
        for item in items:
            link = item.get("link", "")
            # Validate the URL matches expected pattern
            if re.search(info["pattern"], link):
                return link
            # Also check displayed link
            if re.search(info["pattern"], item.get("displayLink", "")):
                return f"https://{item['displayLink']}"
    except Exception:
        pass
    return None


async def _general_search(name: str, nationality: Optional[str]) -> list:
    """General search for public information about the person."""
    query = f'"{name}"'
    if nationality:
        query += f" {nationality}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                params={
                    "key": SEARCH_API_KEY,
                    "cx": SEARCH_CX,
                    "q": query,
                    "num": 5,
                },
            )
        data = r.json()
        snippets = []
        for item in data.get("items", []):
            snippets.append({
                "title": item.get("title", ""),
                "snippet": item.get("snippet", ""),
                "link": item.get("link", ""),
            })
        return snippets
    except Exception:
        return []


def _build_search_urls(name: str) -> dict:
    """Build manual search links (no API key needed)."""
    q = name.replace(" ", "+")
    return {
        "linkedin":  f"https://www.linkedin.com/search/results/people/?keywords={q}",
        "instagram": f"https://www.instagram.com/explore/tags/{q}/",
        "facebook":  f"https://www.facebook.com/search/people/?q={q}",
        "vk":        f"https://vk.com/search?c%5Bsection%5D=people&q={q}",
        "google":    f"https://www.google.com/search?q=%22{q}%22",
    }


def format_for_profile(osint_data: dict) -> dict:
    """Convert raw OSINT results to profile-ready format."""
    social = {}
    for platform in PLATFORMS:
        url = osint_data.get(platform)
        if url:
            social[platform] = url
    return {
        "social_links": social,
        "search_urls": osint_data.get("search_urls", {}),
        "snippets": osint_data.get("raw_snippets", []),
    }
