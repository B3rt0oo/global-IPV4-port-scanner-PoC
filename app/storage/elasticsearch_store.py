from __future__ import annotations

from typing import Optional, Dict, Any, Iterable

from elasticsearch import Elasticsearch, helpers

from app.config import ElasticConfig
from app.logging_setup import get_logger

log = get_logger(__name__)


class ElasticStore:
    def __init__(self, cfg: ElasticConfig):
        self.cfg = cfg
        self.es: Optional[Elasticsearch] = None
        if cfg.enabled:
            auth = None
            if cfg.username and cfg.password:
                auth = (cfg.username, cfg.password)
            self.es = Elasticsearch(cfg.url, basic_auth=auth, verify_certs=False)

    def index_event(self, doc: Dict[str, Any]):
        if not self.es or not self.cfg.enabled:
            return
        try:
            self.es.index(index=self.cfg.index_events, document=doc)
        except Exception as e:
            log.error("es_index_event_failed", error=str(e))

    def index_finding(self, doc: Dict[str, Any]):
        if not self.es or not self.cfg.enabled:
            return
        try:
            self.es.index(index=self.cfg.index_findings, document=doc)
        except Exception as e:
            log.error("es_index_finding_failed", error=str(e))

    def bulk_index_findings(self, docs: Iterable[Dict[str, Any]]):
        if not self.es or not self.cfg.enabled:
            return
        try:
            actions = (
                {"_index": self.cfg.index_findings, "_source": d} for d in docs
            )
            helpers.bulk(self.es, actions, raise_on_error=False)
        except Exception as e:
            log.error("es_bulk_index_failed", error=str(e))

