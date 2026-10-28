"""Daily expiry checks against the latest stored file."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from keyboxstore.notifications import send_notification
from keyboxstore.parser import InvalidKeybox, parse

logger = logging.getLogger(__name__)
CHECK_INTERVAL = 24 * 60 * 60
EXPIRY_WARNING_DAYS = 2


def expiring_certificates(
    keyboxes: list[dict], threshold_days: float, now: datetime
) -> list[dict]:
    deadline = now + timedelta(days=threshold_days)
    matches = []
    for box in keyboxes:
        for key in box["keys"]:
            for index, value in enumerate(key["certificate_expirations"]):
                expires = datetime.fromisoformat(value)
                if expires < deadline:
                    matches.append(
                        {
                            "keybox_index": box["index"],
                            "algorithm": key["algorithm"],
                            "certificate_index": index,
                            "expires_at": value,
                            "expired": expires <= now,
                        }
                    )
    return matches


def check_expiry(
    storage: Path,
    url: str,
    token: str,
    threshold_days: float = EXPIRY_WARNING_DAYS,
    *,
    now: datetime | None = None,
) -> None:
    try:
        _, keyboxes = parse(storage.read_bytes())
    except FileNotFoundError:
        return
    except OSError, InvalidKeybox:
        logger.warning("Unable to read keybox file for expiry check")
        return

    now = now or datetime.now(UTC)
    lines = []
    for cert in expiring_certificates(keyboxes, threshold_days, now):
        status = "expired" if cert["expired"] else "expires"
        lines.append(
            f"Keybox {cert['keybox_index']} ({cert['algorithm'].upper()}): "
            f"{status} {cert['expires_at']} (certificate {cert['certificate_index']})"
        )
    if lines:
        send_notification(
            url,
            token,
            "KeyboxStore expiry warning",
            f"Certificates expiring in less than {threshold_days:g} days "
            "or already expired (UTC):\n" + "\n".join(lines),
        )


async def monitor_expiry(
    storage: Path, url: str, token: str, threshold_days: float = EXPIRY_WARNING_DAYS
) -> None:
    while True:
        await asyncio.to_thread(check_expiry, storage, url, token, threshold_days)
        await asyncio.sleep(CHECK_INTERVAL)
