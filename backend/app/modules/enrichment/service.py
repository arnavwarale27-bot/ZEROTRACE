from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
from sqlalchemy.orm import Session

from app.models.schemas import IOC
from app.models.domain import IOCModel
from app.modules.enrichment.adapters.local import LocalRuleEnricher
from app.modules.enrichment.adapters.external import ExternalThreatIntelAdapter
from app.modules.extraction.service import _model_to_schema
from app.db.repository import ioc_repo


class ThreatIntelEnrichmentService:
    """
    Service coordinating IOC threat intelligence enrichment.
    Applies local heuristics and pluggable external adapters without
    fabricating reputation scores when external providers are unconfigured.
    """

    def __init__(
        self,
        local_enricher: Optional[LocalRuleEnricher] = None,
        external_enricher: Optional[ExternalThreatIntelAdapter] = None,
    ):
        self.local_enricher = local_enricher or LocalRuleEnricher()
        self.external_enricher = external_enricher or ExternalThreatIntelAdapter()

    def enrich_ioc(
        self,
        db: Session,
        ioc_or_id: Union[IOC, str],
    ) -> Optional[IOC]:
        """
        Enriches a single IOC entity and updates its database record.
        """
        if isinstance(ioc_or_id, str):
            model = ioc_repo.get_by_id(db, ioc_or_id)
            if not model:
                return None
            ioc = _model_to_schema(model)
        else:
            ioc = ioc_or_id

        # 1. Run Local Enrichment
        local_result = self.local_enricher.enrich(ioc) or {}

        # 2. Run External Enrichment
        external_result = self.external_enricher.enrich(ioc) or {}

        # 3. Merge Results
        enrichment_meta: Dict[str, Any] = {
            "local": local_result,
            "external": external_result,
            "reputation": local_result.get("reputation", "unknown"),
            "status": local_result.get("status", "enriched"),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

        # Merge tags
        combined_tags = set(ioc.tags)
        combined_tags.update(local_result.get("tags", []))
        combined_tags.update(external_result.get("tags", []))
        ioc.tags = sorted(list(combined_tags))

        # Update confidence score
        if "confidence" in local_result:
            ioc.confidence_score = float(local_result["confidence"])

        # Attach to IOC metadata
        ioc_meta = dict(ioc.metadata or {})
        ioc_meta["enrichment"] = enrichment_meta
        ioc.metadata = ioc_meta

        # Persist updated IOC to database
        saved_model = ioc_repo.save(db, ioc)
        return _model_to_schema(saved_model)

    def enrich_all(
        self,
        db: Session,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """
        Enriches all stored IOC records in the database.
        """
        models = ioc_repo.list_iocs(db, limit=limit)
        enriched_list: List[IOC] = []

        for model in models:
            ioc = _model_to_schema(model)
            enriched = self.enrich_ioc(db, ioc)
            if enriched:
                enriched_list.append(enriched)

        return {
            "total_iocs": len(models),
            "enriched_count": len(enriched_list),
            "iocs": enriched_list,
        }
