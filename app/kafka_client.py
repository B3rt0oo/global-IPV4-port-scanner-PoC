from __future__ import annotations

import json
from typing import Optional, Dict, Any

from aiokafka import AIOKafkaProducer

from app.config import KafkaConfig
from app.logging_setup import get_logger

log = get_logger(__name__)


class KafkaProducer:
    def __init__(self, cfg: KafkaConfig):
        self.cfg = cfg
        self._producer: Optional[AIOKafkaProducer] = None

    async def start(self):
        if not self.cfg.enabled:
            return
        self._producer = AIOKafkaProducer(bootstrap_servers=self.cfg.bootstrap_servers)
        await self._producer.start()
        log.info("kafka_producer_started", servers=self.cfg.bootstrap_servers)

    async def stop(self):
        if self._producer:
            await self._producer.stop()
            self._producer = None

    async def send_json(self, topic: str, obj: Dict[str, Any]):
        if not self._producer or not self.cfg.enabled:
            return
        try:
            payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            await self._producer.send_and_wait(topic, payload)
        except Exception as e:
            log.error("kafka_send_failed", error=str(e), topic=topic)

