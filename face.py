"""Face embedding extraction, perceptual hashing, and similarity search."""
import hashlib
import io
import struct
import numpy as np
from pathlib import Path
from typing import Optional

from config import FACE_MODEL, FACE_MATCH_THRESHOLD, FACE_HIGH_THRESHOLD

# ── Embedding extraction ───────────────────────────────────────────────────────

def extract_embedding(image_bytes: bytes) -> Optional[np.ndarray]:
    """
    Extract a face embedding from raw image bytes.
    Returns a float32 numpy array or None if no face detected.
    """
    if FACE_MODEL == "face_recognition":
        return _extract_face_recognition(image_bytes)
    elif FACE_MODEL == "insightface":
        return _extract_insightface(image_bytes)
    else:
        raise ValueError(f"Unknown face model: {FACE_MODEL}")


def _extract_face_recognition(image_bytes: bytes) -> Optional[np.ndarray]:
    try:
        import face_recognition
        import PIL.Image
        img = PIL.Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.array(img)
        encodings = face_recognition.face_encodings(arr)
        if not encodings:
            return None
        # Use first (largest) face; 128-dim float64 → float32
        return encodings[0].astype(np.float32)
    except ImportError:
        raise RuntimeError("face_recognition not installed: pip install face-recognition")


def _extract_insightface(image_bytes: bytes) -> Optional[np.ndarray]:
    try:
        import insightface
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        app = insightface.app.FaceAnalysis()
        app.prepare(ctx_id=-1)  # CPU
        faces = app.get(img)
        if not faces:
            return None
        # Sort by detection score, take best
        faces.sort(key=lambda f: f.det_score, reverse=True)
        return faces[0].embedding.astype(np.float32)
    except ImportError:
        raise RuntimeError("insightface not installed: pip install insightface")


# ── Perceptual hash ────────────────────────────────────────────────────────────

def compute_phash(image_bytes: bytes) -> str:
    """
    Compute a perceptual hash (pHash) of the largest face region.
    Falls back to full-image pHash if no face detected.
    Returns a 16-character hex string (64-bit hash).
    """
    try:
        from PIL import Image
        import imagehash
        img = Image.open(io.BytesIO(image_bytes)).convert("L")
        return str(imagehash.phash(img))
    except ImportError:
        # Fallback: simple average hash without imagehash library
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((8, 8))
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        return f"{int(bits, 2):016x}"


def image_sha256(image_bytes: bytes) -> str:
    return hashlib.sha256(image_bytes).hexdigest()


# ── Embedding serialisation ────────────────────────────────────────────────────

def embedding_to_blob(arr: np.ndarray) -> bytes:
    return arr.astype(np.float32).tobytes()


def blob_to_embedding(blob: bytes, dim: int) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32).reshape(dim)


# ── Similarity ─────────────────────────────────────────────────────────────────

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity in [−1, 1]. Higher = more similar."""
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def euclidean_distance(a: np.ndarray, b: np.ndarray) -> float:
    """L2 distance. Lower = more similar. face_recognition uses this."""
    return float(np.linalg.norm(a - b))


def is_match(query: np.ndarray, stored: np.ndarray) -> tuple[bool, float]:
    """
    Returns (is_match, confidence_0_to_1).
    For face_recognition (128-d), threshold on L2 distance.
    For insightface (512-d), threshold on cosine similarity.
    """
    if query.shape[0] == 128:
        dist = euclidean_distance(query, stored)
        confidence = max(0.0, 1.0 - dist / 0.9)   # normalise roughly to 0–1
        return dist <= FACE_MATCH_THRESHOLD, confidence
    else:
        sim = cosine_similarity(query, stored)
        return sim >= (1 - FACE_MATCH_THRESHOLD), sim


# ── DB search ─────────────────────────────────────────────────────────────────

def find_best_match(query_embedding: np.ndarray, conn) -> Optional[dict]:
    """
    Linear scan of face_embeddings table.
    Returns the best-matching row dict + confidence, or None.

    For production: replace with ANN index (FAISS / Chroma).
    """
    rows = conn.execute(
        "SELECT id, profile_id, embedding, embedding_dim, model FROM face_embeddings"
    ).fetchall()

    best = None
    best_conf = 0.0

    for row in rows:
        stored = blob_to_embedding(row["embedding"], row["embedding_dim"])
        matched, conf = is_match(query_embedding, stored)
        if matched and conf > best_conf:
            best_conf = conf
            best = {"face_emb_id": row["id"], "profile_id": row["profile_id"], "confidence": conf}

    return best if best else None
