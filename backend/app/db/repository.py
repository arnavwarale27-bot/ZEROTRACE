from typing import Generic, TypeVar, Type, Optional, List, Any
from sqlalchemy.orm import Session
from app.db.base import Base
from app.models.domain import (
    SecurityEventModel,
    IncidentModel,
    IOCModel,
    TimelineEventModel,
    MitreTechniqueModel,
    EvidenceModel,
    InvestigationResultModel,
    RecommendedActionModel,
)

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Generic Data Repository Abstraction.
    Decouples domain business logic from specific database ORM implementations.
    """

    def __init__(self, model: Type[ModelType]):
        self.model = model

    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        pk_col = (
            getattr(self.model, "event_id", None)
            or getattr(self.model, "technique_id", None)
            or getattr(self.model, "id", None)
        )
        if pk_col is not None:
            return db.query(self.model).filter(pk_col == id).first()
        return None

    def get_multi(self, db: Session, *, skip: int = 0, limit: int = 100) -> List[ModelType]:
        return db.query(self.model).offset(skip).limit(limit).all()

    def create(self, db: Session, *, obj_in: Any) -> ModelType:
        if isinstance(obj_in, dict):
            db_obj = self.model(**obj_in)
        elif hasattr(obj_in, "model_dump"):
            db_obj = self.model(**obj_in.model_dump())
        else:
            db_obj = self.model(**obj_in.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, *, id: Any) -> Optional[ModelType]:
        obj = self.get(db, id)
        if obj:
            db.delete(obj)
            db.commit()
        return obj


class SecurityEventRepository(BaseRepository[SecurityEventModel]):
    def __init__(self):
        super().__init__(SecurityEventModel)

    def get_by_event_id(self, db: Session, event_id: str) -> Optional[SecurityEventModel]:
        return db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).first()

    def list_events(
        self,
        db: Session,
        *,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEventModel]:
        query = db.query(SecurityEventModel)
        if source:
            query = query.filter(SecurityEventModel.source.ilike(f"%{source}%"))
        if severity:
            query = query.filter(SecurityEventModel.severity == severity.upper())
        if event_type:
            query = query.filter(SecurityEventModel.event_type.ilike(f"%{event_type}%"))
        return query.order_by(SecurityEventModel.timestamp.desc()).offset(skip).limit(limit).all()

    def save(self, db: Session, event_in: Any) -> SecurityEventModel:
        data = event_in.model_dump() if hasattr(event_in, "model_dump") else (event_in if isinstance(event_in, dict) else event_in.dict())
        existing = self.get_by_event_id(db, data["event_id"])
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = SecurityEventModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class IncidentRepository(BaseRepository[IncidentModel]):
    def __init__(self):
        super().__init__(IncidentModel)

    def get_by_id(self, db: Session, incident_id: str) -> Optional[IncidentModel]:
        return db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()

    def list_incidents(
        self,
        db: Session,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IncidentModel]:
        query = db.query(IncidentModel)
        if status:
            query = query.filter(IncidentModel.status == status.upper())
        if severity:
            query = query.filter(IncidentModel.severity == severity.upper())
        return query.order_by(IncidentModel.created_at.desc()).offset(skip).limit(limit).all()

    def save(self, db: Session, incident_in: Any) -> IncidentModel:
        data = incident_in.model_dump() if hasattr(incident_in, "model_dump") else (incident_in if isinstance(incident_in, dict) else incident_in.dict())
        existing = self.get_by_id(db, data["id"])
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = IncidentModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class IOCRepository(BaseRepository[IOCModel]):
    def __init__(self):
        super().__init__(IOCModel)

    def get_by_id(self, db: Session, ioc_id: str) -> Optional[IOCModel]:
        return db.query(IOCModel).filter(IOCModel.id == ioc_id).first()

    def get_by_type_and_value(self, db: Session, ioc_type: str, value: str) -> Optional[IOCModel]:
        return db.query(IOCModel).filter(
            IOCModel.type == ioc_type.lower(),
            IOCModel.value == value.strip(),
        ).first()

    def list_iocs(
        self,
        db: Session,
        *,
        ioc_type: Optional[str] = None,
        tag: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IOCModel]:
        query = db.query(IOCModel)
        if ioc_type:
            query = query.filter(IOCModel.type == ioc_type.lower())
        if tag:
            query = query.filter(IOCModel.tags.contains([tag]))
        return query.order_by(IOCModel.last_seen.desc()).offset(skip).limit(limit).all()

    def save(self, db: Session, ioc_in: Any) -> IOCModel:
        data = ioc_in.model_dump() if hasattr(ioc_in, "model_dump") else (ioc_in if isinstance(ioc_in, dict) else ioc_in.dict())
        if "metadata" in data and "metadata_json" not in data:
            data["metadata_json"] = data.pop("metadata")

        existing = self.get_by_id(db, data["id"])
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = IOCModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class TimelineEventRepository(BaseRepository[TimelineEventModel]):
    def __init__(self):
        super().__init__(TimelineEventModel)

    def get_by_incident_id(self, db: Session, incident_id: str) -> List[TimelineEventModel]:
        return (
            db.query(TimelineEventModel)
            .filter(TimelineEventModel.incident_id == incident_id)
            .order_by(TimelineEventModel.sequence.asc(), TimelineEventModel.timestamp.asc())
            .all()
        )

    def save(self, db: Session, timeline_in: Any) -> TimelineEventModel:
        data = timeline_in.model_dump() if hasattr(timeline_in, "model_dump") else (timeline_in if isinstance(timeline_in, dict) else timeline_in.dict())
        existing = db.query(TimelineEventModel).filter(TimelineEventModel.id == data["id"]).first()
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = TimelineEventModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class MitreTechniqueRepository(BaseRepository[MitreTechniqueModel]):
    def __init__(self):
        super().__init__(MitreTechniqueModel)

    def get_by_technique_id(self, db: Session, technique_id: str) -> Optional[MitreTechniqueModel]:
        return db.query(MitreTechniqueModel).filter(MitreTechniqueModel.technique_id == technique_id).first()

    def save(self, db: Session, tech_in: Any) -> MitreTechniqueModel:
        data = tech_in.model_dump() if hasattr(tech_in, "model_dump") else (tech_in if isinstance(tech_in, dict) else tech_in.dict())
        existing = self.get_by_technique_id(db, data["technique_id"])
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = MitreTechniqueModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class EvidenceRepository(BaseRepository[EvidenceModel]):
    def __init__(self):
        super().__init__(EvidenceModel)

    def get_by_incident_id(self, db: Session, incident_id: str) -> List[EvidenceModel]:
        return db.query(EvidenceModel).filter(EvidenceModel.incident_id == incident_id).all()

    def save(self, db: Session, evidence_in: Any) -> EvidenceModel:
        data = evidence_in.model_dump() if hasattr(evidence_in, "model_dump") else (evidence_in if isinstance(evidence_in, dict) else evidence_in.dict())
        existing = db.query(EvidenceModel).filter(EvidenceModel.id == data["id"]).first()
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = EvidenceModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class InvestigationResultRepository(BaseRepository[InvestigationResultModel]):
    def __init__(self):
        super().__init__(InvestigationResultModel)

    def get_by_incident_id(self, db: Session, incident_id: str) -> Optional[InvestigationResultModel]:
        return (
            db.query(InvestigationResultModel)
            .filter(InvestigationResultModel.incident_id == incident_id)
            .order_by(InvestigationResultModel.created_at.desc())
            .first()
        )

    def save(self, db: Session, res_in: Any) -> InvestigationResultModel:
        data = res_in.model_dump() if hasattr(res_in, "model_dump") else (res_in if isinstance(res_in, dict) else res_in.dict())
        existing = db.query(InvestigationResultModel).filter(InvestigationResultModel.id == data["id"]).first()
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = InvestigationResultModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


class RecommendedActionRepository(BaseRepository[RecommendedActionModel]):
    def __init__(self):
        super().__init__(RecommendedActionModel)

    def get_by_incident_id(self, db: Session, incident_id: str) -> List[RecommendedActionModel]:
        return db.query(RecommendedActionModel).filter(RecommendedActionModel.incident_id == incident_id).all()

    def save(self, db: Session, action_in: Any) -> RecommendedActionModel:
        data = action_in.model_dump() if hasattr(action_in, "model_dump") else (action_in if isinstance(action_in, dict) else action_in.dict())
        existing = db.query(RecommendedActionModel).filter(RecommendedActionModel.id == data["id"]).first()
        if existing:
            for field, val in data.items():
                setattr(existing, field, val)
            db.commit()
            db.refresh(existing)
            return existing
        else:
            db_obj = RecommendedActionModel(**data)
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj


security_event_repo = SecurityEventRepository()
incident_repo = IncidentRepository()
ioc_repo = IOCRepository()
timeline_repo = TimelineEventRepository()
mitre_repo = MitreTechniqueRepository()
evidence_repo = EvidenceRepository()
investigation_repo = InvestigationResultRepository()
action_repo = RecommendedActionRepository()
