"""
memory/vector_store.py — Semantic API Payload Store

Uses ChromaDB (local) to embed and retrieve intercepted API payloads.

Why embeddings here?
  The Mutator agent needs to generalise attacks across the application.
  When it tests an IDOR on /api/v1/orders, it should automatically recall
  that /api/v1/profile uses a structurally similar { user_id: N } pattern,
  and attack both.  Keyword search can't do this; vector similarity can.

Embedding model: ChromaDB's default "all-MiniLM-L6-v2" (runs locally,
  no extra API key).  Fast enough for typical scan sizes (<10k payloads).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Optional

import chromadb
from chromadb.utils import embedding_functions

from config import config

logger = logging.getLogger("VectorStore")

# ── PII patterns for pre-hashing before sending to external LLMs ──────────────
_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),                       # SSN
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), # phone
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),                              # Visa CC
]


def _sanitise_for_llm(payload: dict) -> dict:
    """
    Replace PII-looking values with their SHA-256 hashes before the
    payload is included in a prompt sent to an external LLM API.

    Only active when config.HASH_PII is True.
    """
    if not config.HASH_PII:
        return payload

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            for pattern in _PII_PATTERNS:
                value = pattern.sub(
                    lambda m: "PII:" + hashlib.sha256(m.group().encode()).hexdigest()[:12],
                    value,
                )
            return value
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(i) for i in value]
        return value

    return scrub(payload)


# ── VectorStore ───────────────────────────────────────────────────────────────

class VectorStore:
    """
    Chroma-backed store for intercepted API request/response pairs.

    Each document is the JSON-serialised request body + URL.
    Metadata includes the endpoint, HTTP method, and a flag for whether
    the payload contains numeric / UUID identifiers (IDOR candidates).
    """

    def __init__(self):
        self._client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
        self._ef = embedding_functions.DefaultEmbeddingFunction()
        self._collection = self._client.get_or_create_collection(
            name=config.COLLECTION_NAME,
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "VectorStore ready — %d payloads in collection.",
            self._collection.count(),
        )

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def add_request(
        self,
        endpoint: str,
        method: str,
        request_body: dict,
        response_status: int,
        response_body: str,
        dom_context: str = "",
    ) -> str:
        """
        Embed and store an intercepted API request.

        Returns the document ID.
        """
        doc_id = hashlib.sha256(
            (endpoint + json.dumps(request_body, sort_keys=True)).encode()
        ).hexdigest()[:20]

        # Build the text document to embed
        document_text = (
            f"ENDPOINT: {endpoint}\n"
            f"METHOD: {method}\n"
            f"REQUEST_BODY: {json.dumps(request_body, indent=2)}\n"
            f"DOM_CONTEXT: {dom_context[:300]}"
        )

        metadata = {
            "endpoint":       endpoint,
            "method":         method,
            "response_status": response_status,
            "has_int_id":     self._has_integer_id(request_body),
            "has_uuid":       self._has_uuid(request_body),
            "has_price":      self._has_price_field(request_body),
            "has_role":       self._has_role_field(request_body),
            "request_body":   json.dumps(request_body)[:1000],   # Chroma metadata limit
            "response_body":  response_body[:500],
        }

        try:
            self._collection.upsert(
                ids=[doc_id],
                documents=[document_text],
                metadatas=[metadata],
            )
        except Exception as exc:
            logger.warning("Upsert failed for %s: %s", endpoint, exc)

        return doc_id

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def query_similar(
        self,
        query: str,
        n_results: int = 10,
        filter_metadata: Optional[dict] = None,
    ) -> list[dict]:
        """
        Semantic search over stored payloads.

        Example query: "endpoints with user IDs or ownership checks"
        Returns a list of dicts with keys: endpoint, request_body, metadata.
        """
        kwargs: dict = {"query_texts": [query], "n_results": n_results}
        if filter_metadata:
            kwargs["where"] = filter_metadata

        try:
            results = self._collection.query(**kwargs)
        except Exception as exc:
            logger.error("Vector query failed: %s", exc)
            return []

        payloads = []
        for i, meta in enumerate(results["metadatas"][0]):
            try:
                body = json.loads(meta.get("request_body", "{}"))
            except json.JSONDecodeError:
                body = {}
            payloads.append({
                "endpoint":     meta.get("endpoint", ""),
                "method":       meta.get("method", ""),
                "request_body": body,
                "response_status": meta.get("response_status"),
                "has_int_id":   meta.get("has_int_id", False),
                "has_uuid":     meta.get("has_uuid", False),
                "has_price":    meta.get("has_price", False),
                "has_role":     meta.get("has_role", False),
                "distance":     results["distances"][0][i],
                "sanitised_body": _sanitise_for_llm(body),
            })
        return payloads

    def get_idor_candidates(self) -> list[dict]:
        """Retrieve payloads with integer IDs or UUIDs — prime IDOR targets."""
        return self.query_similar(
            "API call with user ID, resource ID, or owner parameter",
            filter_metadata={"$or": [{"has_int_id": True}, {"has_uuid": True}]},
            n_results=20,
        )

    def get_price_candidates(self) -> list[dict]:
        """Retrieve payloads with price or quantity fields (cart manipulation)."""
        return self.query_similar(
            "cart checkout payment price total quantity discount",
            filter_metadata={"has_price": True},
            n_results=10,
        )

    def get_role_candidates(self) -> list[dict]:
        """Retrieve payloads with role or privilege fields."""
        return self.query_similar(
            "role admin privilege access level permission",
            filter_metadata={"has_role": True},
            n_results=10,
        )

    def count(self) -> int:
        return self._collection.count()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _has_integer_id(body: dict) -> bool:
        id_keys = {"id", "user_id", "userid", "account_id", "order_id",
                   "product_id", "resource_id", "owner_id"}
        return any(
            isinstance(v, int) and _matches(k, id_keys)
            for k, v in _flatten(body).items()
        )

    @staticmethod
    def _has_uuid(body: dict) -> bool:
        uuid_re = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
        )
        return any(
            isinstance(v, str) and uuid_re.fullmatch(v)
            for v in _flatten(body).values()
        )

    @staticmethod
    def _has_price_field(body: dict) -> bool:
        price_keys = {"price", "total", "amount", "quantity", "qty",
                      "discount", "cost", "subtotal"}
        return any(_matches(k, price_keys) for k in _flatten(body))

    @staticmethod
    def _has_role_field(body: dict) -> bool:
        role_keys = {"role", "roles", "permission", "permissions",
                     "access_level", "is_admin", "admin", "privilege"}
        return any(_matches(k, role_keys) for k in _flatten(body))


# ── Utility ───────────────────────────────────────────────────────────────────

def _flatten(obj: Any, prefix: str = "") -> dict:
    """
    Recursively flatten a nested dict/list into {dotted.path: value} pairs.

    List items get an index suffix, e.g. "items[0].price", so that fields
    nested inside cart/line-item arrays — the normal shape of a checkout
    payload — are visible to the has_* detectors above. Detectors match via
    _matches(), which strips the trailing [i] and singularizes before
    comparing, so "items[0].price", "cart.price" and "prices[0]" (a bare
    scalar array) all correctly register as a price field.
    """
    result: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            result.update(_flatten(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            full_key = f"{prefix}[{i}]"
            result.update(_flatten(item, full_key))
    else:
        result[prefix] = obj
    return result


def _field_name(key: str) -> str:
    """
    Extract the matchable field name from a flattened key, stripping any
    trailing array-index suffix, e.g. "items[0].price" -> "price",
    "user_ids[2]" -> "user_ids".
    """
    return re.sub(r"\[\d+\]$", "", key.split(".")[-1])


def _pluralized_forms(word: str) -> set[str]:
    """
    All plausible spellings (singular + plural) of a known pattern word.

    We deliberately only ever pluralize FROM the small, fixed keyword
    list — never try to singularize an arbitrary observed field name.
    Singularizing an unknown word is ambiguous and lossy: is "status"
    already singular, or a stripped plural of "statu"? There's no way to
    tell from the string alone, and an earlier version of this function
    that tried mangled "status" -> "statu". Pluralizing a *known* word
    has no such ambiguity — we control the input.
    """
    forms = {word, f"{word}s"}
    if len(word) > 1 and word.endswith("y") and word[-2] not in "aeiou":
        forms.add(word[:-1] + "ies")
    if word.endswith(("s", "x", "z", "ch", "sh")):
        forms.add(word + "es")
    return forms


def _matches(key: str, patterns: set[str]) -> bool:
    """True if key's field name matches any pattern, singular or plural."""
    name = _field_name(key).lower()
    return any(name in _pluralized_forms(p) for p in patterns)