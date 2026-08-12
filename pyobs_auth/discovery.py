"""OIDC discovery document fetch, cached per issuer for the life of the process."""

from __future__ import annotations

import threading
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class DiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None


_cache: dict[str, DiscoveryDocument] = {}
_lock = threading.Lock()


def fetch_discovery_document(discovery_url: str, *, timeout: float = 10.0) -> DiscoveryDocument:
    with _lock:
        cached = _cache.get(discovery_url)
    if cached is not None:
        return cached

    response = requests.get(discovery_url, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    document = DiscoveryDocument(
        issuer=data["issuer"],
        authorization_endpoint=data["authorization_endpoint"],
        token_endpoint=data["token_endpoint"],
        userinfo_endpoint=data["userinfo_endpoint"],
        jwks_uri=data["jwks_uri"],
        end_session_endpoint=data.get("end_session_endpoint"),
    )
    with _lock:
        _cache[discovery_url] = document
    return document


def clear_discovery_cache() -> None:
    """Only needed for tests - the cache is otherwise process-lifetime."""
    with _lock:
        _cache.clear()
