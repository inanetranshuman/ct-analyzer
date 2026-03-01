from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from time import monotonic

import websockets

from ct_analyzer.config import Settings


LOGGER = logging.getLogger(__name__)


async def stream_certstream_events(settings: Settings) -> AsyncIterator[dict]:
    backoff = 1
    while True:
        try:
            async with websockets.connect(settings.ingest.certstream_url, ping_interval=20, ping_timeout=20) as websocket:
                LOGGER.info("Connected to CertStream at %s", settings.ingest.certstream_url)
                backoff = 1
                raw_messages = 0
                certificate_updates = 0
                last_progress_log = monotonic()
                last_message_at = monotonic()
                while True:
                    try:
                        raw_message = await asyncio.wait_for(websocket.recv(), timeout=30)
                    except asyncio.TimeoutError:
                        LOGGER.warning(
                            "CertStream connected but no raw messages have arrived in %.0f seconds",
                            monotonic() - last_message_at,
                        )
                        continue

                    now = monotonic()
                    raw_messages += 1
                    last_message_at = now
                    payload = json.loads(raw_message)
                    message_type = payload.get("message_type", "unknown")
                    if now - last_progress_log >= 30:
                        LOGGER.info(
                            "CertStream traffic: raw_messages=%s certificate_updates=%s last_message_type=%s",
                            raw_messages,
                            certificate_updates,
                            message_type,
                        )
                        last_progress_log = now
                    if message_type == "certificate_update":
                        certificate_updates += 1
                        yield payload
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.warning("CertStream connection failed: %s", exc)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
