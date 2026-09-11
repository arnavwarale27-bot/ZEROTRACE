from fastapi import APIRouter
from app.core.config import settings
from app.models.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Backend System Health Check")
def health_check() -> HealthResponse:
    """
    Basic health check endpoint returning system status and current API version.
    """
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        app=settings.PROJECT_NAME
    )
