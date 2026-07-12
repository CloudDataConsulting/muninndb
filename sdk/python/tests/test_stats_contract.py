"""Offline tests for the vault-scoped stats SDK contract."""

import asyncio

from muninn.client import MuninnClient


def test_stats_preserves_scope_and_availability() -> None:
    client = MuninnClient("http://example.invalid")
    captured: dict[str, object] = {}

    async def fake_request(method: str, path: str, **kwargs: object) -> dict[str, object]:
        captured.update(method=method, path=path, params=kwargs.get("params"))
        return {
            "engram_count": 42,
            "vault_count": 1,
            "stats_scope": "vault",
            "storage_bytes": 0,
            "storage_bytes_available": False,
            "index_size": 0,
            "index_size_available": False,
        }

    client._request = fake_request  # type: ignore[method-assign]
    stats = asyncio.run(client.stats(vault="client-a"))

    assert captured == {
        "method": "GET",
        "path": "/api/stats",
        "params": {"vault": "client-a"},
    }
    assert stats.engram_count == 42
    assert stats.vault_count == 1
    assert stats.stats_scope == "vault"
    assert not stats.storage_bytes_available
    assert not stats.index_size_available


def test_stats_marks_legacy_response_scope_unknown() -> None:
    client = MuninnClient("http://example.invalid")

    async def fake_request(method: str, path: str, **kwargs: object) -> dict[str, object]:
        del method, path, kwargs
        return {
            "engram_count": 42,
            "vault_count": 7,
            "storage_bytes": 1024,
        }

    client._request = fake_request  # type: ignore[method-assign]
    stats = asyncio.run(client.stats(vault="client-a"))

    assert stats.stats_scope == "unknown"
    assert not stats.storage_bytes_available
    assert not stats.index_size_available
