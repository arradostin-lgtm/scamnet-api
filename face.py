"""Face analysis via Claude Vision API + perceptual hashing."""
import base64
import hashlib
import io
import json
from typing import Optional


# ── Perceptual hash ───────────────────────────────────────────────────────────

def compute_phash(image_bytes: bytes) -> str:
    """64-bit perceptual hash as 16-char hex string."""
    try:
        from PIL import Image
        import imagehash
        img = Image.open(io.BytesIO(image_bytes)).convert("L")
        return str(imagehash.phash(img))
    except Exception:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((8, 8))
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        return f"{int(bits, 2):016x}"


def image_sha256(image_bytes: bytes) -> str:
    return hashlib.sha256(image_bytes).hexdigest()


def image_to_base64(image_bytes: bytes) -> str:
    return base64.b64encode(image_bytes).decode()


def _media_type(image_bytes: bytes) -> str:
    if image_bytes[:4] == b'\x89PNG':
        return "image/png"
    if image_bytes[:2] in (b'\xff\xd8',):
        return "image/jpeg"
    if b'WEBP' in image_bytes[:12]:
        return "image/webp"
    return "image/jpeg"


# ── Claude Vision: face comparison ────────────────────────────────────────────

def compare_faces_with_claude(
    query_bytes: bytes,
    stored_profiles: list,  # [{"profile_id": str, "seed_photo_path": str, "name": str}]
    seed_photos_dir: Optional[str] = None,
) -> dict:
    """
    Compare query photo against scammer profiles using Claude Vision.
    Profile photos are read from disk (seed_photos_dir) — never stored in DB.
    query_bytes is processed in memory and never persisted.
    Returns: {matched, profile_id, confidence, reasoning}
    """
    from pathlib import Path

    if seed_photos_dir is None:
        seed_photos_dir = str(Path(__file__).parent / "seed_photos")
    photos_dir = Path(seed_photos_dir)

    loadable = []
    for prof in stored_profiles[:5]:
        filename = prof.get("seed_photo_path")
        if not filename:
            continue
        photo_path = photos_dir / filename
        if not photo_path.exists():
            continue
        photo_bytes = photo_path.read_bytes()
        loadable.append({**prof, "_bytes": photo_bytes})

    if not loadable:
        return {
            "matched": False,
            "profile_id": None,
            "confidence": 0.0,
            "reasoning": "No reference photos available on disk",
        }

    content = [
        {
            "type": "text",
            "text": (
                "You are a face verification system for a fraud detection service.\n"
                "Compare the QUERY face image with each PROFILE image below.\n"
                "Determine if the QUERY shows the SAME real person as any PROFILE.\n"
                "Focus on: bone structure, eyes, nose, mouth, ears, jawline.\n"
                "Ignore: lighting, angle, age ±5 years, expression, accessories.\n\n"
                "QUERY IMAGE:"
            ),
        },
        {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": _media_type(query_bytes),
                "data": image_to_base64(query_bytes),
            },
        },
    ]

    for i, prof in enumerate(loadable):
        content.append({
            "type": "text",
            "text": f"\nPROFILE {i + 1} (id={prof['profile_id']}, name={prof.get('name', '?')}):",
        })
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": _media_type(prof["_bytes"]),
                "data": image_to_base64(prof["_bytes"]),
            },
        })

    content.append({
        "type": "text",
        "text": (
            "\nRespond ONLY with valid JSON (no markdown):\n"
            '{"matched": true|false, "profile_id": "id string or null", '
            '"confidence": 0.0-1.0, "reasoning": "1-2 sentences"}\n'
            "Set matched=true ONLY if confidence >= 0.70."
        ),
    })

    try:
        from anthropic import Anthropic
        msg = Anthropic().messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            messages=[{"role": "user", "content": content}],
        )
        text = msg.content[0].text.strip()
        start, end = text.find("{"), text.rfind("}") + 1
        if start == -1:
            raise ValueError("No JSON in response")
        return json.loads(text[start:end])
    except Exception as e:
        return {
            "matched": False,
            "profile_id": None,
            "confidence": 0.0,
            "reasoning": f"Comparison error: {e}",
        }


# ── Claude Vision: AI-generated image detection ───────────────────────────────

def detect_ai_image(image_bytes: bytes) -> dict:
    """
    Detect if a face photo is AI-generated using Claude Vision + local heuristics.
    Returns: {is_ai, confidence, model_hint}
    """
    local_score = _local_ai_heuristic(image_bytes)

    try:
        from anthropic import Anthropic
        msg = Anthropic().messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Is this face photo AI-generated (GAN, deepfake, Midjourney, DALL-E, "
                            "Stable Diffusion, etc.)?\n"
                            "Signs: unnatural skin, blurry background, asymmetric ears, garbled accessories, "
                            "inconsistent lighting, overly perfect features.\n"
                            "Respond ONLY with JSON: "
                            '{"is_ai": true|false, "confidence": 0.0-1.0, '
                            '"model_hint": "midjourney|dalle|stable_diffusion|deepfake|real|unknown"}'
                        ),
                    },
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": _media_type(image_bytes),
                            "data": image_to_base64(image_bytes),
                        },
                    },
                ],
            }],
        )
        text = msg.content[0].text.strip()
        start, end = text.find("{"), text.rfind("}") + 1
        result = json.loads(text[start:end])
        # Blend Claude's read with local heuristic (70/30)
        blended = 0.7 * float(result.get("confidence", 0.5)) + 0.3 * local_score
        return {
            "is_ai": blended >= 0.5,
            "confidence": round(blended, 3),
            "model_hint": result.get("model_hint", "unknown"),
        }
    except Exception:
        return {
            "is_ai": local_score >= 0.5,
            "confidence": round(local_score, 3),
            "model_hint": "unknown",
        }


def _local_ai_heuristic(image_bytes: bytes) -> float:
    """Quick local AI-image probability (0–1) without API calls."""
    signals = []

    # No EXIF camera data → more likely AI
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        exif = getattr(img, "_getexif", lambda: None)()
        if exif is None:
            signals.append(0.6)
        else:
            from PIL.ExifTags import TAGS
            tags = {TAGS.get(k, k): v for k, v in exif.items()}
            signals.append(0.15 if any(k in tags for k in ("Make", "Model")) else 0.55)
    except Exception:
        signals.append(0.5)

    # Low hue variance → GAN artifact
    try:
        import numpy as np
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("HSV").resize((64, 64))
        arr = np.array(img)
        hue_std = float(arr[:, :, 0].std())
        signals.append(0.65 if hue_std < 12 else (0.45 if hue_std < 25 else 0.2))
    except Exception:
        signals.append(0.5)

    return sum(signals) / len(signals)
