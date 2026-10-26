import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

from keyboxstore import expiry


def test_expiry_threshold_and_all_keyboxes(tmp_path, monkeypatch):
    now = datetime(2026, 10, 26, tzinfo=UTC)

    offsets = [
        timedelta(days=10),
        timedelta(days=2),
        timedelta(days=2, seconds=-1),
        timedelta(days=1),
        timedelta(seconds=-1),
    ]
    boxes = [
        {
            "index": index,
            "keys": [
                {
                    "algorithm": "ecdsa",
                    "leaf": {"not_valid_after": (now + offset).isoformat()},
                }
            ],
        }
        for index, offset in enumerate(offsets)
    ]
    storage = tmp_path / "keybox.xml"
    storage.write_bytes(b"latest file")
    monkeypatch.setattr(expiry, "parse", lambda data: (None, boxes))
    send = Mock()
    monkeypatch.setattr(expiry, "send_notification", send)
    expiry.check_expiry(storage, "https://ntfy.example/topic", "token", now=now)
    send.assert_called_once()
    message = send.call_args.args[3]
    assert "less than 2 days" in message
    assert "Keybox 0" not in message
    assert "Keybox 1" not in message
    assert "Keybox 2 (ECDSA): expires" in message
    assert "Keybox 3 (ECDSA): expires" in message
    assert "Keybox 4 (ECDSA): expired" in message
    assert (now + offsets[2]).isoformat() in message

    boxes[:] = boxes[:2]
    send.reset_mock()
    expiry.check_expiry(storage, "https://ntfy.example/topic", "token", now=now)
    send.assert_not_called()


def test_missing_invalid_and_replaced_file(tmp_path, monkeypatch):
    storage = tmp_path / "keybox.xml"
    send = Mock()
    monkeypatch.setattr(expiry, "send_notification", send)
    now = datetime(2026, 10, 26, tzinfo=UTC)
    expiry.check_expiry(storage, "https://ntfy.example/topic", "", now=now)
    storage.write_bytes(b"invalid XML")
    expiry.check_expiry(storage, "https://ntfy.example/topic", "", now=now)
    send.assert_not_called()
    storage.write_bytes((Path(__file__).parent / "fixtures/keybox.xml").read_bytes())
    expiry.check_expiry(storage, "https://ntfy.example/topic", "", now=now)
    send.assert_called_once()
    assert "ECDSA" in send.call_args.args[3]
    assert "RSA" not in send.call_args.args[3]


def test_daily_schedule_and_cancellation(tmp_path, monkeypatch):
    async def scenario():
        calls = []
        checked_twice = asyncio.Event()
        original_sleep = asyncio.sleep

        async def run_check(function, *args):
            calls.append(args)
            if len(calls) == 2:
                checked_twice.set()

        async def wait_interval(seconds):
            assert seconds == 86400
            if len(calls) == 1:
                await original_sleep(0)
            else:
                await asyncio.Event().wait()

        monkeypatch.setattr(expiry.asyncio, "to_thread", run_check)
        monkeypatch.setattr(expiry.asyncio, "sleep", wait_interval)
        storage = tmp_path / "keybox.xml"
        task = asyncio.create_task(expiry.monitor_expiry(storage, "url", "token"))
        await asyncio.wait_for(checked_twice.wait(), timeout=1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert task.cancelled()
        assert calls == [(storage, "url", "token")] * 2

    asyncio.run(scenario())
