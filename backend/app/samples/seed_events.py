import json
from pathlib import Path
from app.core.database import SessionLocal, init_db
from app.modules.ingestion.service import LogIngestionService

SAMPLES_DIR = Path(__file__).parent
SAMPLE_FILE = SAMPLES_DIR / "sample_logs.json"


def seed_sample_events():
    """Seed the database with sample security events."""
    init_db()
    if not SAMPLE_FILE.exists():
        print(f"Sample file not found at {SAMPLE_FILE}")
        return

    with open(SAMPLE_FILE, "r", encoding="utf-8") as f:
        logs = json.load(f)

    db = SessionLocal()
    try:
        service = LogIngestionService()
        result = service.ingest_batch(db, logs)
        print(f"Seeding completed: {result['ingested_count']}/{result['total']} events ingested.")
        if result["failed_count"] > 0:
            print(f"Errors: {result['errors']}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_sample_events()
