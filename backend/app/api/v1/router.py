from fastapi import APIRouter
from app.api.v1.endpoints import health, events, correlation, incidents, iocs, intelligence

api_v1_router = APIRouter()
api_v1_router.include_router(health.router, tags=["Health"])
api_v1_router.include_router(events.router)
api_v1_router.include_router(correlation.router)
api_v1_router.include_router(incidents.router)
api_v1_router.include_router(iocs.router)
api_v1_router.include_router(intelligence.router)
