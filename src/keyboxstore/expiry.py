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


def check_expiry(
    storage: Path, url: str, token: str, *, now: datetime | None = None
) -> None:
    try:
        _, keyboxes = parse(storage.read_bytes())
    except FileNotFoundError:
        return
    except OSError, InvalidKeybox:
        logger.warning("Unable to read keybox file for expiry check")
        return

    now = now or datetime.now(UTC)
    deadline = now + timedelta(days=EXPIRY_WARNING_DAYS)
    lines = []
    for box in keyboxes:
        for key in box["keys"]:
            expires = datetime.fromisoformat(key["leaf"]["not_valid_after"])
            if expires < deadline:
                status = "expired" if expires <= now else "expires"
                lines.append(
                    f"Keybox {box['index']} ({key['algorithm'].upper()}): "
                    f"{status} {expires.isoformat()}"
                )
    if lines:
        send_notification(
            url,
            token,
            "KeyboxStore expiry warning",
            f"Certificates expiring in less than {EXPIRY_WARNING_DAYS} days "
            "or already expired (UTC):\n" + "\n".join(lines),
        )


async def monitor_expiry(storage: Path, url: str, token: str) -> None:
    while True:
        await asyncio.to_thread(check_expiry, storage, url, token)
        await asyncio.sleep(CHECK_INTERVAL)
