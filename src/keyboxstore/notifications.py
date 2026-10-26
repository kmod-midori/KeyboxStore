"""Optional, best-effort ntfy notifications."""

import logging

import httpx

logger = logging.getLogger(__name__)


def notify_upload(url: str, token: str, count: int, first_keybox: dict) -> None:
    lines = [
        f"Keybox file replaced successfully ({count} keyboxes).",
        "First keybox certificate validity (UTC):",
    ]
    for key in first_keybox["keys"]:
        leaf = key["leaf"]
        lines.append(
            f"{key['algorithm'].upper()}: "
            f"{leaf['not_valid_before']} to {leaf['not_valid_after']}"
        )
    send_notification(url, token, "KeyboxStore updated", "\n".join(lines))


def send_notification(url: str, token: str, title: str, message: str) -> None:
    headers = {"Title": title, "Content-Type": "text/plain"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            response = client.post(
                url,
                content=message,
                headers=headers,
            )
            response.raise_for_status()
    except httpx.HTTPError, ValueError:
        # Do not log the topic URL, token, or response body.
        logger.warning("ntfy notification failed")
