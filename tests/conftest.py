import pytest


@pytest.fixture(autouse=True)
def disable_external_notifications(monkeypatch):
    monkeypatch.delenv("NTFY_URL", raising=False)
    monkeypatch.delenv("NTFY_TOKEN", raising=False)
    monkeypatch.delenv("NTFY_EXPIRY_DAYS", raising=False)
    monkeypatch.delenv("API_EXPIRY_DAYS", raising=False)
