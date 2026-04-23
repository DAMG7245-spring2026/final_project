"""BM25 index over advisory_chunks.chunk_text.

In-memory inverted index built with rank_bm25. Source of truth lives in
Snowflake; this module pulls chunk_text once, tokenizes, and keeps the
BM25Okapi instance plus a chunk_id list so search() can map ranks back
to chunk_ids.

The index is persisted as a pickle under data/bm25_index.pkl so app
restarts don't have to re-pull the whole table from Snowflake every time.
"""
import logging
import os
import pickle
import re
import time
from dataclasses import dataclass
from typing import Optional

import nltk
from nltk.corpus import stopwords
from rank_bm25 import BM25Okapi

from app.services.snowflake import get_snowflake_service

logger = logging.getLogger(__name__)


DEFAULT_INDEX_PATH = "data/bm25_index.pkl"

# Structured security IDs we want preserved as atomic tokens so exact-match
# queries like "CVE-2024-1234" or "aa23-215a" stay intact through
# tokenization. Without this, `_WORD_RE` splits on `-` / `.` and collapses
# high-IDF identifiers into many low-IDF fragments (e.g. "aa23-215a" ->
# ["aa23","215a"]), which kills BM25 recall on entity-heavy queries.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_ADVISORY_RE = re.compile(
    r"\b(?:"
    r"aa\d{2}-\d{3,}[a-z]?"              # joint CSA: aa23-215a
    r"|ar\d{2}-\d{3,}[a-z]?"             # analysis report: ar20-198b
    r"|mar-\d+(?:-\d+)?(?:\.v\d+)?"      # malware analysis: mar-10296782-2.v1
    r")\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WORD_RE = re.compile(r"[a-zA-Z0-9]+")


def _load_stopwords() -> frozenset[str]:
    """Load NLTK English stopwords, downloading the corpus on first use."""
    try:
        words = stopwords.words("english")
    except LookupError:
        logger.info("[bm25] nltk stopwords corpus not found; downloading...")
        nltk.download("stopwords", quiet=True)
        words = stopwords.words("english")
    return frozenset(words)


_STOPWORDS: frozenset[str] = _load_stopwords()


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    ids = (
        [m.lower() for m in _CVE_RE.findall(text)]
        + [m.lower() for m in _CWE_RE.findall(text)]
        + [m.lower() for m in _MITRE_RE.findall(text)]
        + [m.lower() for m in _ADVISORY_RE.findall(text)]
        + [m.lower() for m in _IPV4_RE.findall(text)]
    )
    clean = _CVE_RE.sub(" ", text)
    clean = _CWE_RE.sub(" ", clean)
    clean = _MITRE_RE.sub(" ", clean)
    clean = _ADVISORY_RE.sub(" ", clean)
    clean = _IPV4_RE.sub(" ", clean)
    words = [
        w.lower()
        for w in _WORD_RE.findall(clean)
        if w.lower() not in _STOPWORDS
    ]
    return ids + words


@dataclass
class BM25SearchHit:
    chunk_id: str
    score: float
    rank: int


class BM25Index:
    """In-memory BM25 index keyed by chunk_id."""

    def __init__(
        self,
        bm25: BM25Okapi,
        chunk_ids: list[str],
        built_at: float,
        num_docs: int,
    ):
        self.bm25 = bm25
        self.chunk_ids = chunk_ids
        self.built_at = built_at
        self.num_docs = num_docs

    @classmethod
    def build_from_snowflake(cls) -> "BM25Index":
        logger.info("[bm25] pulling chunk_text from Snowflake...")
        t0 = time.time()
        sf = get_snowflake_service()
        with sf.cursor() as cur:
            cur.execute(
                "SELECT chunk_id, chunk_text "
                "FROM advisory_chunks "
                "WHERE chunk_text IS NOT NULL"
            )
            rows = cur.fetchall()
        logger.info(
            "[bm25] fetched %d chunks in %.1fs", len(rows), time.time() - t0
        )

        if not rows:
            raise RuntimeError("no chunk_text rows found in advisory_chunks")

        t1 = time.time()
        chunk_ids = [r[0] for r in rows]
        tokenized = [tokenize(r[1]) for r in rows]
        logger.info("[bm25] tokenized in %.1fs", time.time() - t1)

        t2 = time.time()
        bm25 = BM25Okapi(tokenized)
        logger.info("[bm25] BM25Okapi built in %.1fs", time.time() - t2)

        return cls(
            bm25=bm25,
            chunk_ids=chunk_ids,
            built_at=time.time(),
            num_docs=len(chunk_ids),
        )

    def save(self, path: str = DEFAULT_INDEX_PATH) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "bm25": self.bm25,
                    "chunk_ids": self.chunk_ids,
                    "built_at": self.built_at,
                    "num_docs": self.num_docs,
                },
                f,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        logger.info("[bm25] saved index (%d docs) -> %s", self.num_docs, path)

    @classmethod
    def load(cls, path: str = DEFAULT_INDEX_PATH) -> "BM25Index":
        with open(path, "rb") as f:
            data = pickle.load(f)
        logger.info(
            "[bm25] loaded index (%d docs, built %s) <- %s",
            data["num_docs"],
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data["built_at"])),
            path,
        )
        return cls(
            bm25=data["bm25"],
            chunk_ids=data["chunk_ids"],
            built_at=data["built_at"],
            num_docs=data["num_docs"],
        )

    def search(self, query: str, top_n: int = 50) -> list[BM25SearchHit]:
        tokens = tokenize(query)
        if not tokens:
            return []
        scores = self.bm25.get_scores(tokens)
        # argsort desc, take top_n, drop zero-scored
        ranked_idx = sorted(
            range(len(scores)), key=lambda i: scores[i], reverse=True
        )[:top_n]
        hits: list[BM25SearchHit] = []
        for rank, idx in enumerate(ranked_idx, start=1):
            s = float(scores[idx])
            if s <= 0:
                break
            hits.append(
                BM25SearchHit(chunk_id=self.chunk_ids[idx], score=s, rank=rank)
            )
        return hits


# Process-level singleton so FastAPI handlers share one index in memory.
_index: Optional[BM25Index] = None


def get_bm25_index() -> BM25Index:
    if _index is None:
        raise RuntimeError(
            "BM25 index not initialized. Call load_or_build_bm25_index() "
            "during app startup."
        )
    return _index


def load_or_build_bm25_index(
    path: str = DEFAULT_INDEX_PATH,
    force_rebuild: bool = False,
) -> BM25Index:
    """Load pickled index if present, otherwise build from Snowflake and save.

    Safe to call during FastAPI lifespan startup.
    """
    global _index
    if _index is not None and not force_rebuild:
        return _index

    if not force_rebuild and os.path.exists(path):
        try:
            _index = BM25Index.load(path)
            return _index
        except Exception as e:
            logger.warning(
                "[bm25] failed to load %s (%s); rebuilding from Snowflake",
                path,
                e,
            )

    _index = BM25Index.build_from_snowflake()
    _index.save(path)
    return _index


def rebuild_bm25_index(path: str = DEFAULT_INDEX_PATH) -> dict:
    """Unconditionally rebuild the BM25 index from Snowflake and save to pickle.

    Refreshes the process-level singleton so in-process callers see the new
    index immediately. Intended for ingestion pipelines (e.g. Airflow) that
    need to rebuild after chunks change.
    """
    global _index
    t0 = time.time()
    index = BM25Index.build_from_snowflake()
    index.save(path)
    _index = index
    elapsed = time.time() - t0
    logger.info(
        "[bm25] rebuild complete: num_docs=%d path=%s elapsed_sec=%.3f",
        index.num_docs, path, elapsed,
    )
    return {
        "num_docs": index.num_docs,
        "path": path,
        "built_at": index.built_at,
        "elapsed_sec": elapsed,
    }
