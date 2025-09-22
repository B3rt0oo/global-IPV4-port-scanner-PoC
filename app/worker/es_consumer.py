from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

from aiokafka import AIOKafkaConsumer

from app.config import load_config
from app.logging_setup import setup_logging, get_logger
from app.otel import init_otel
from app.storage.elasticsearch_store import ElasticStore


async def run_consumer():
    cfg = load_config()
    setup_logging()
    if cfg.otel.enabled:
        init_otel(cfg.otel.service_name + "-worker", cfg.otel.endpoint)

    log = get_logger("worker")
    if not cfg.kafka.enabled:
        log.error("kafka_disabled")
        return

    es = ElasticStore(cfg.elastic)
    consumer = AIOKafkaConsumer(
        cfg.kafka.topic_findings,
        bootstrap_servers=cfg.kafka.bootstrap_servers,
        enable_auto_commit=True,
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )
    await consumer.start()
    log.info("worker_started", topic=cfg.kafka.topic_findings)
    try:
        buffer: List[Dict[str, Any]] = []
        while True:
            msg = await consumer.getone()
            buffer.append(msg.value)
            if len(buffer) >= 500:
                es.bulk_index_findings(buffer)
                log.info("bulk_index", count=len(buffer))
                buffer.clear()
    finally:
        if buffer:
            es.bulk_index_findings(buffer)
        await consumer.stop()


def main():
    asyncio.run(run_consumer())


if __name__ == "__main__":
    main()

