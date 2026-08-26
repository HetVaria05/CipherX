import os
import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("MONGODB_DB_NAME", "cipherx")
COLLECTION_NAME = "scans"

_mongo_client = None
_db = None
_scans_collection = None
_in_memory_scans: List[Dict[str, Any]] = []


def get_db():
    global _mongo_client, _db, _scans_collection
    if _scans_collection is not None:
        return _scans_collection

    if not MONGODB_URI:
        logger.info("No MONGODB_URI configured. Running with in-memory scan storage.")
        return None

    try:
        from pymongo import MongoClient, DESCENDING
        _mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2500)
        # Test connection
        _mongo_client.admin.command('ping')
        _db = _mongo_client[DATABASE_NAME]
        _scans_collection = _db[COLLECTION_NAME]
        _scans_collection.create_index([("created_at", DESCENDING)])
        _scans_collection.create_index([("normalized_url", DESCENDING)])
        logger.info("Successfully connected to MongoDB.")
        return _scans_collection
    except Exception as err:
        logger.warning(f"MongoDB connection failed ({err}). Falling back to in-memory store.")
        _mongo_client = None
        _scans_collection = None
        return None


def save_scan(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Saves a scan record with timestamp and basic summary metrics.
    """
    record = {
        "url": result.get("url"),
        "normalized_url": result.get("normalized_url"),
        "risk_score": result.get("risk_score", 0),
        "classification": result.get("classification", "LOW"),
        "confidence": result.get("confidence", 0.0),
        "signals_count": len(result.get("signals", [])),
        "threat_intel_source": (
            result.get("features", {}).get("threat_intel_match", {}).get("source")
            if result.get("features") else None
        ),
        "detected_brand": (
            result.get("brand_analysis", {}).get("impersonated_brand")
            if result.get("brand_analysis") else None
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "timestamp": time.time(),
        "details": {
            "signals": result.get("signals", []),
            "adversarial_findings": result.get("adversarial_findings", []),
            "explanation": result.get("explanation"),
        }
    }

    collection = get_db()
    if collection is not None:
        try:
            inserted = collection.insert_one(record)
            record["id"] = str(inserted.inserted_id)
            return record
        except Exception as err:
            logger.error(f"Failed to insert into MongoDB ({err}). Saving to memory.")

    # In-memory fallback
    record["id"] = f"mem_{int(time.time() * 1000)}"
    _in_memory_scans.insert(0, record)
    if len(_in_memory_scans) > 100:
        _in_memory_scans.pop()

    return record


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent scans.
    """
    collection = get_db()
    if collection is not None:
        try:
            from pymongo import DESCENDING
            cursor = collection.find(
                {},
                {"details": 0}
            ).sort("timestamp", DESCENDING).limit(limit)
            
            scans = []
            for doc in cursor:
                doc["id"] = str(doc.get("_id", doc.get("id")))
                if "_id" in doc:
                    del doc["_id"]
                scans.append(doc)
            return scans
        except Exception as err:
            logger.error(f"Error fetching from MongoDB ({err})")

    # In-memory fallback
    return [
        {k: v for k, v in scan.items() if k != "details"}
        for scan in _in_memory_scans[:limit]
    ]


def get_scan_stats() -> Dict[str, Any]:
    """
    Calculates overall scan statistics (total scans, critical count, safe count).
    """
    collection = get_db()
    if collection is not None:
        try:
            total = collection.count_documents({})
            critical = collection.count_documents({"classification": {"$in": ["HIGH", "CRITICAL"]}})
            clean = collection.count_documents({"classification": "LOW"})
            return {
                "total_scans": total,
                "threats_blocked": critical,
                "clean_scans": clean,
                "db_status": "connected_mongodb"
            }
        except Exception as err:
            logger.error(f"Failed to fetch stats from MongoDB ({err})")

    total = len(_in_memory_scans)
    critical = sum(1 for s in _in_memory_scans if s.get("classification") in ["HIGH", "CRITICAL"])
    clean = sum(1 for s in _in_memory_scans if s.get("classification") == "LOW")
    return {
        "total_scans": total,
        "threats_blocked": critical,
        "clean_scans": clean,
        "db_status": "in_memory_fallback"
    }
