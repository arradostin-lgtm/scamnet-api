"""
Voice embedding extraction, perceptual hashing, similarity search,
and synthetic-voice detection.

Models supported:
  resemblyzer  — 256-d d-vector (default, pure Python)
  speechbrain  — 192-d x-vector (higher accuracy, heavier deps)
"""
from __future__ import annotations
import hashlib
import io
import math
import tempfile
import os
from typing import Optional

import numpy as np

import config
from database import db


# ── Embedding extraction ────────────────────────────────────────────────────────

def extract_embedding(audio_bytes: bytes) -> Optional[np.ndarray]:
    if config.VOICE_MODEL == "resemblyzer":
        return _extract_resemblyzer(audio_bytes)
    elif config.VOICE_MODEL == "speechbrain":
        return _extract_speechbrain(audio_bytes)
    else:
        raise ValueError(f"Unknown voice model: {config.VOICE_MODEL}")


def _extract_resemblyzer(audio_bytes: bytes) -> Optional[np.ndarray]:
    try:
        from resemblyzer import VoiceEncoder, preprocess_wav
        encoder = VoiceEncoder()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(audio_bytes)
            path = f.name
        try:
            wav = preprocess_wav(path)
            emb = encoder.embed_utterance(wav)
            return emb.astype(np.float32)
        finally:
            os.unlink(path)
    except ImportError:
        raise RuntimeError("resemblyzer not installed: pip install resemblyzer")
    except Exception as e:
        print(f"[voice] resemblyzer error: {e}")
        return None


def _extract_speechbrain(audio_bytes: bytes) -> Optional[np.ndarray]:
    try:
        import torchaudio, torch
        from speechbrain.pretrained import SpeakerRecognition
        verif = SpeakerRecognition.from_hparams(
            source="speechbrain/spkrec-xvect-voxceleb",
            savedir="/tmp/speechbrain_xvect",
        )
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(audio_bytes)
            path = f.name
        try:
            signal, sr = torchaudio.load(path)
            emb = verif.encode_batch(signal)
            return emb.squeeze().numpy().astype(np.float32)
        finally:
            os.unlink(path)
    except ImportError:
        raise RuntimeError("speechbrain not installed: pip install speechbrain")
    except Exception as e:
        print(f"[voice] speechbrain error: {e}")
        return None


# ── Perceptual fingerprint ────────────────────────────────────────────────────

def audio_fingerprint(audio_bytes: bytes) -> str:
    """
    Lightweight voice fingerprint (SHA-256 of spectral features).
    Not a perceptual hash, but stable for the same recording.
    """
    try:
        import librosa
        import soundfile as sf
        with io.BytesIO(audio_bytes) as buf:
            y, sr = librosa.load(buf, sr=16000, duration=30)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
        mean = mfcc.mean(axis=1)
        packed = mean.astype(np.float32).tobytes()
        return hashlib.sha256(packed).hexdigest()
    except Exception:
        return hashlib.sha256(audio_bytes[:8192]).hexdigest()


def audio_sha256(audio_bytes: bytes) -> str:
    return hashlib.sha256(audio_bytes).hexdigest()


# ── Serialisation ──────────────────────────────────────────────────────────────

def embedding_to_blob(arr: np.ndarray) -> bytes:
    return arr.astype(np.float32).tobytes()


def blob_to_embedding(blob: bytes, dim: int) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32).reshape(dim)


# ── Similarity ─────────────────────────────────────────────────────────────────

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def is_voice_match(query: np.ndarray, stored: np.ndarray) -> tuple[bool, float]:
    """Returns (matched, confidence 0–1)."""
    sim = cosine_similarity(query, stored)
    return sim >= config.VOICE_MATCH_THRESHOLD, sim


def find_best_voice_match(query_embedding: np.ndarray, conn) -> Optional[dict]:
    """Linear scan of voice_embeddings. Replace with ANN for production."""
    rows = conn.execute(
        "SELECT id, profile_id, embedding, embedding_dim FROM voice_embeddings"
    ).fetchall()
    best = None
    best_conf = 0.0
    for row in rows:
        stored = blob_to_embedding(row["embedding"], row["embedding_dim"])
        matched, conf = is_voice_match(query_embedding, stored)
        if matched and conf > best_conf:
            best_conf = conf
            best = {"voice_emb_id": row["id"], "profile_id": row["profile_id"], "confidence": conf}
    return best if best else None


# ── Synthetic voice detection ─────────────────────────────────────────────────

def detect_synthetic(audio_bytes: bytes) -> dict:
    """
    Multi-signal TTS/voice-cloning detector.
    Returns: {is_synthetic, confidence, method}
    """
    signals = []

    # Signal 1: spectral flatness (TTS voices are often flatter than real speech)
    s1 = _spectral_flatness_score(audio_bytes)
    if s1 is not None:
        signals.append(s1)

    # Signal 2: pitch continuity (TTS produces unnaturally smooth F0)
    s2 = _pitch_continuity_score(audio_bytes)
    if s2 is not None:
        signals.append(s2)

    # Signal 3: silence ratio (TTS often has too-clean silence segments)
    s3 = _silence_ratio_score(audio_bytes)
    if s3 is not None:
        signals.append(s3)

    if not signals:
        return {"is_synthetic": False, "confidence": 0.5, "method": "unavailable"}

    confidence = sum(signals) / len(signals)
    return {
        "is_synthetic": confidence >= 0.55,
        "confidence": round(confidence, 3),
        "method": "ensemble",
    }


def _spectral_flatness_score(audio_bytes: bytes) -> Optional[float]:
    """High spectral flatness → more noise-like → less likely TTS."""
    try:
        import librosa
        with io.BytesIO(audio_bytes) as buf:
            y, sr = librosa.load(buf, sr=16000, duration=15)
        flatness = librosa.feature.spectral_flatness(y=y).mean()
        # Real voices: flatness ~0.001–0.05; TTS: often < 0.005
        if flatness < 0.003:
            return 0.7
        if flatness < 0.01:
            return 0.45
        return 0.2
    except Exception:
        return None


def _pitch_continuity_score(audio_bytes: bytes) -> Optional[float]:
    """Unnaturally smooth pitch (low F0 variance) → TTS."""
    try:
        import librosa
        with io.BytesIO(audio_bytes) as buf:
            y, sr = librosa.load(buf, sr=16000, duration=15)
        f0, _, _ = librosa.pyin(y, fmin=50, fmax=400, sr=sr)
        voiced = f0[~np.isnan(f0)]
        if len(voiced) < 20:
            return None
        cv = voiced.std() / (voiced.mean() + 1e-9)   # coefficient of variation
        # Real speech: cv > 0.15; TTS often < 0.08
        if cv < 0.06:
            return 0.75
        if cv < 0.12:
            return 0.5
        return 0.2
    except Exception:
        return None


def _silence_ratio_score(audio_bytes: bytes) -> Optional[float]:
    """Unnatural silence distribution can indicate TTS/cloning."""
    try:
        import librosa
        with io.BytesIO(audio_bytes) as buf:
            y, sr = librosa.load(buf, sr=16000, duration=15)
        rms = librosa.feature.rms(y=y)[0]
        threshold = rms.max() * 0.01
        silence_ratio = (rms < threshold).mean()
        # TTS often < 5% silence or very clean transitions
        if silence_ratio < 0.03:
            return 0.6
        if silence_ratio < 0.08:
            return 0.4
        return 0.2
    except Exception:
        return None
