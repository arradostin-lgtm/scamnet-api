"""Face analysis: InsightFace embeddings + Claude Vision + perceptual hashing."""
import base64
import hashlib
import io
import json
import os
from typing import Optional

import numpy as np


# ── InsightFace: real face recognition ────────────────────────────────────────

_face_app = None


def _get_face_app():
    """Load InsightFace once and cache in module scope."""
    global _face_app
    if _face_app is not None:
        return _face_app
    try:
        import insightface
        app = insightface.app.FaceAnalysis(
            name="buffalo_sc",                   # lightweight ~100 MB model
            providers=["CPUExecutionProvider"],
        )
        app.prepare(ctx_id=-1, det_size=(640, 640))
        _face_app = app
        print("[face] InsightFace loaded (buffalo_sc, CPU)")
        return app
    except Exception as e:
        print(f"[face] InsightFace unavailable: {e}")
        return None


def compute_face_embedding(image_bytes: bytes) -> Optional[bytes]:
    """
    Compute 512-dim ArcFace embedding for the largest face in the image.
    Returns raw float32 bytes (stored as BLOB) or None if no face detected.
    """
    from PIL import Image
    app = _get_face_app()
    if app is None:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img)
        faces = app.get(arr)
        if not faces:
            return None
        # Use the largest detected face
        face = max(faces, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
        emb = face.embedding.astype(np.float32)
        return emb.tobytes()
    except Exception as e:
        print(f"[face] embedding error: {e}")
        return None


def embedding_similarity(blob_a: bytes, blob_b: bytes) -> float:
    """Cosine similarity between two stored embeddings (float32 blobs). Range: -1..1."""
    a = np.frombuffer(blob_a, dtype=np.float32)
    b = np.frombuffer(blob_b, dtype=np.float32)
    norm_a, norm_b = np.linalg.norm(a), np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


# Threshold: InsightFace cosine similarity for "same person"
# buffalo_sc: >0.40 → likely same person, >0.50 → high confidence
FACE_MATCH_THRESHOLD = 0.40


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


def analyze_exif(image_bytes: bytes) -> dict:
    """
    Analyze EXIF metadata for fraud risk signals.
    AI-generated and screenshot photos typically have no EXIF or suspicious software field.
    Returns: {has_exif, camera_make, camera_model, software, date_taken, gps_present, risk_signals}
    """
    result = {
        "has_exif": False,
        "camera_make": None,
        "camera_model": None,
        "software": None,
        "date_taken": None,
        "gps_present": False,
        "risk_signals": [],
    }
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        exif = getattr(img, "_getexif", lambda: None)()

        if exif is None:
            result["risk_signals"].append("Нет EXIF — возможно AI или скриншот")
            return result

        result["has_exif"] = True
        make    = exif.get(271)   # Make
        model   = exif.get(272)   # Model
        software = exif.get(305)  # Software
        date    = exif.get(36867) # DateTimeOriginal
        gps     = exif.get(34853) # GPSInfo

        result["camera_make"]  = str(make).strip()    if make    else None
        result["camera_model"] = str(model).strip()   if model   else None
        result["software"]     = str(software).strip() if software else None
        result["date_taken"]   = str(date).strip()    if date    else None
        result["gps_present"]  = bool(gps)

        # Flag AI generation software
        _AI_SW = ["stable diffusion", "midjourney", "dall-e", "firefly", "imagen",
                  "generative", "nightcafe", "canva ai"]
        if software:
            sw_low = str(software).lower()
            if any(hint in sw_low for hint in _AI_SW):
                result["risk_signals"].append(f"ПО: {software} — AI-генератор")

        if not make and not model:
            result["risk_signals"].append("Нет данных о камере в EXIF")

        if not date:
            result["risk_signals"].append("Нет даты съёмки в EXIF")

    except Exception:
        result["risk_signals"].append("Не удалось прочитать EXIF")

    return result


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
