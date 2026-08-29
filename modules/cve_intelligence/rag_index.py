"""TF-IDF retrieval index over CVE database for RAG.

Lazy-loads scikit-learn. Builds index from cve_entries + cve_technologies tables.
Persists as validated JSON. Used to ground AI payload generation and enrich findings.
"""
import json
import logging
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_INDEX_FORMAT = "deep-eye-cve-rag"
_INDEX_VERSION = 1
_MAX_INDEX_BYTES = 64 * 1024 * 1024
_MAX_DOCUMENTS = 250_000
_MAX_DOCUMENT_LENGTH = 100_000


def _ensure_sklearn(interactive: bool = True) -> bool:
    """Return whether scikit-learn is installed; never install at runtime."""
    del interactive  # retained for API compatibility
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


def _new_vectorizer():
    from sklearn.feature_extraction.text import TfidfVectorizer

    return TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        max_features=50000,
        sublinear_tf=True,
    )


class CVERagIndex:
    """TF-IDF retrieval index over CVE corpus."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        rag_config = config.get("rag", {}) if isinstance(config.get("rag"), dict) else {}

        self.index_path = Path(rag_config.get("index_path", "data/cve_rag_index.json"))
        self.top_k = int(rag_config.get("top_k", 5))
        self.min_score = float(rag_config.get("min_score", 0.15))
        self.auto_rebuild = bool(rag_config.get("auto_rebuild", True))

        self._vectorizer = None
        self._matrix = None
        self._cve_meta: List[Dict] = []
        self._documents: List[str] = []
        self._loaded = False

    def is_loaded(self) -> bool:
        return self._loaded

    def is_stale(self, cve_db_path: str) -> bool:
        """Check if index is missing or older than CVE DB."""
        if not self.index_path.exists():
            return True
        if not Path(cve_db_path).exists():
            return False
        return self.index_path.stat().st_mtime < Path(cve_db_path).stat().st_mtime

    def load(self) -> bool:
        """Load and rebuild an index from the non-executable JSON format."""
        if not self.index_path.exists():
            return False
        if not _ensure_sklearn(interactive=False):
            logger.warning("RAG: scikit-learn not available; cannot load index")
            return False

        try:
            if self.index_path.is_symlink():
                raise ValueError("symbolic-link index files are not accepted")
            if self.index_path.stat().st_size > _MAX_INDEX_BYTES:
                raise ValueError("index exceeds the maximum supported size")
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("index root must be an object")
            if payload.get("format") != _INDEX_FORMAT or payload.get("version") != _INDEX_VERSION:
                raise ValueError("unsupported or legacy RAG index format; rebuild the index")
            documents = payload.get("documents")
            cve_meta = payload.get("cve_meta")
            if not isinstance(documents, list) or not isinstance(cve_meta, list):
                raise ValueError("index documents and metadata must be lists")
            if not documents or len(documents) != len(cve_meta):
                raise ValueError("index documents and metadata are inconsistent")
            if len(documents) > _MAX_DOCUMENTS:
                raise ValueError("index contains too many documents")
            if any(
                not isinstance(document, str) or len(document) > _MAX_DOCUMENT_LENGTH
                for document in documents
            ):
                raise ValueError("index contains an invalid document")
            if any(not isinstance(entry, dict) for entry in cve_meta):
                raise ValueError("index contains invalid CVE metadata")

            vectorizer = _new_vectorizer()
            matrix = vectorizer.fit_transform(documents)
            self._vectorizer = vectorizer
            self._matrix = matrix
            self._documents = list(documents)
            self._cve_meta = list(cve_meta)
            self._loaded = True
            logger.info(
                f"RAG index loaded: {len(self._cve_meta)} CVEs from {self.index_path}"
            )
            return True
        except Exception as e:
            logger.error(f"RAG: failed to load index: {e}")
            self._loaded = False
            return False

    def save(self) -> None:
        """Persist source documents and metadata as atomic, mode-0600 JSON."""
        if self._vectorizer is None or self._matrix is None or not self._documents:
            raise RuntimeError("Cannot save unbuilt index")

        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format": _INDEX_FORMAT,
            "version": _INDEX_VERSION,
            "documents": self._documents,
            "cve_meta": self._cve_meta,
            "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "doc_count": len(self._cve_meta),
        }
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.index_path.parent),
                prefix=f".{self.index_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                os.chmod(handle.name, 0o600)
                json.dump(payload, handle, ensure_ascii=False, allow_nan=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temp_path), str(self.index_path))
            temp_path = None
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
        logger.info(f"RAG index saved: {self.index_path} ({len(self._cve_meta)} CVEs)")

    def build(self, cve_db_path: str, interactive: bool = True) -> bool:
        """Build TF-IDF index from CVE SQLite database."""
        if not _ensure_sklearn(interactive=interactive):
            logger.warning("RAG: scikit-learn unavailable; skipping index build")
            return False

        if not Path(cve_db_path).exists():
            logger.warning(f"RAG: CVE DB not found at {cve_db_path}")
            return False

        rows = self._load_cve_rows(cve_db_path)
        if not rows:
            logger.info("RAG: CVE table empty; skipping build")
            return False

        documents = []
        meta = []
        for row in rows:
            cve_id, description, cvss_score, severity, technologies = row
            tech_str = " ".join(technologies) if technologies else ""
            doc = f"{description or ''} {tech_str}".strip()
            if not doc:
                continue
            documents.append(doc)
            meta.append(
                {
                    "cve_id": cve_id,
                    "description": description or "",
                    "cvss_score": cvss_score or 0.0,
                    "severity": severity or "",
                    "affected_products": technologies or [],
                }
            )

        if not documents:
            logger.info("RAG: no documents after filter; skipping build")
            return False

        vectorizer = _new_vectorizer()
        matrix = vectorizer.fit_transform(documents)

        self._vectorizer = vectorizer
        self._matrix = matrix
        self._cve_meta = meta
        self._documents = documents
        self._loaded = True
        logger.info(f"RAG index built: {len(meta)} CVEs, vocab={len(vectorizer.vocabulary_)}")
        return True

    def _load_cve_rows(self, cve_db_path: str) -> List[tuple]:
        """Fetch CVE rows + aggregated technologies."""
        conn = sqlite3.connect(cve_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cve_entries'"
            )
            if cursor.fetchone() is None:
                logger.warning("RAG: cve_entries table missing")
                return []

            cursor.execute(
                """
                SELECT c.cve_id, c.description, c.cvss_score, c.severity,
                       GROUP_CONCAT(t.technology, '|')
                FROM cve_entries c
                LEFT JOIN cve_technologies t ON c.cve_id = t.cve_id
                GROUP BY c.cve_id
                """
            )
            rows = []
            for cve_id, desc, cvss, sev, techs in cursor.fetchall():
                tech_list = techs.split("|") if techs else []
                rows.append((cve_id, desc, cvss, sev, tech_list))
            return rows
        finally:
            conn.close()

    def search(self, query: str, top_k: Optional[int] = None) -> List[Dict]:
        """Search index. Returns list of hits with score, filtered by min_score."""
        if not self._loaded or not query or not query.strip():
            return []

        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np

        k = top_k if top_k is not None else self.top_k
        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix)[0]

        top_indices = np.argsort(-scores)[:k]

        results = []
        for idx in top_indices:
            score = float(scores[idx])
            if score < self.min_score:
                continue
            entry = dict(self._cve_meta[idx])
            entry["score"] = score
            results.append(entry)
        return results
