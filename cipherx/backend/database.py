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
_db_connection_attempted = False
_in_memory_scans: List[Dict[str, Any]] = []


def get_db():
    global _mongo_client, _db, _scans_collection, _db_connection_attempted
    if _scans_collection is not None:
        return _scans_collection

    if _db_connection_attempted:
        return None

    if not MONGODB_URI:
        logger.info("No MONGODB_URI configured. Running with in-memory scan storage.")
        _db_connection_attempted = True
        return None

    _db_connection_attempted = True
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


# ==========================================
# Caching & User Quota Management
# ==========================================

_in_memory_cache: Dict[str, Dict[str, Any]] = {}
_in_memory_quotas: Dict[str, Dict[str, Any]] = {}

CACHE_COLLECTION_NAME = "scan_cache"
QUOTA_COLLECTION_NAME = "user_quotas"
DEFAULT_DAILY_QUOTA = 3


def get_cached_scan(url: str) -> Optional[Dict[str, Any]]:
    """
    Checks if a URL has been scanned recently (TTL 24 hours).
    Returns cached analysis result if valid, else None.
    """
    now = time.time()
    ttl_seconds = 24 * 3600

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            cache_col = _db[CACHE_COLLECTION_NAME]
            doc = cache_col.find_one({"url": url})
            if doc and (now - doc.get("timestamp", 0)) < ttl_seconds:
                return doc.get("result")
        except Exception as err:
            logger.error(f"Error querying scan cache from MongoDB: {err}")

    # Fallback in-memory cache
    cached = _in_memory_cache.get(url)
    if cached and (now - cached.get("timestamp", 0)) < ttl_seconds:
        return cached.get("result")

    return None


def cache_scan_result(url: str, result: Dict[str, Any]):
    """
    Stores an advanced scan result in cache with timestamp.
    """
    now = time.time()
    record = {
        "url": url,
        "result": result,
        "timestamp": now,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            cache_col = _db[CACHE_COLLECTION_NAME]
            cache_col.update_one({"url": url}, {"$set": record}, upsert=True)
            return
        except Exception as err:
            logger.error(f"Error caching scan in MongoDB: {err}")

    _in_memory_cache[url] = record


def get_user_quota(user_id: str) -> Dict[str, Any]:
    """
    Retrieves user daily quota status for advanced scans (default 3 per 24 hours).
    """
    now = time.time()
    day_seconds = 24 * 3600

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            quota_col = _db[QUOTA_COLLECTION_NAME]
            doc = quota_col.find_one({"user_id": user_id})
            if doc:
                last_reset = doc.get("last_reset", 0)
                used = doc.get("used", 0)
                # Reset if 24 hours have passed
                if now - last_reset >= day_seconds:
                    quota_col.update_one(
                        {"user_id": user_id},
                        {"$set": {"used": 0, "last_reset": now}}
                    )
                    return {"used": 0, "total": DEFAULT_DAILY_QUOTA, "remaining": DEFAULT_DAILY_QUOTA}
                remaining = max(0, DEFAULT_DAILY_QUOTA - used)
                return {"used": used, "total": DEFAULT_DAILY_QUOTA, "remaining": remaining}
        except Exception as err:
            logger.error(f"Error reading user quota from MongoDB: {err}")

    # Fallback in-memory quota
    quota_info = _in_memory_quotas.get(user_id)
    if not quota_info or (now - quota_info.get("last_reset", 0)) >= day_seconds:
        _in_memory_quotas[user_id] = {"used": 0, "last_reset": now}
        return {"used": 0, "total": DEFAULT_DAILY_QUOTA, "remaining": DEFAULT_DAILY_QUOTA}

    used = quota_info.get("used", 0)
    remaining = max(0, DEFAULT_DAILY_QUOTA - used)
    return {"used": used, "total": DEFAULT_DAILY_QUOTA, "remaining": remaining}


def consume_user_quota(user_id: str) -> bool:
    """
    Deducts 1 advanced scan credit from user's quota if available.
    Returns True if permitted and deducted, False if quota exhausted.
    """
    status = get_user_quota(user_id)
    if status["remaining"] <= 0:
        return False

    now = time.time()
    new_used = status["used"] + 1

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            quota_col = _db[QUOTA_COLLECTION_NAME]
            quota_col.update_one(
                {"user_id": user_id},
                {"$set": {"used": new_used}, "$setOnInsert": {"last_reset": now}},
                upsert=True
            )
            return True
        except Exception as err:
            logger.error(f"Error updating user quota in MongoDB: {err}")

    current = _in_memory_quotas.get(user_id, {"last_reset": now, "used": 0})
    current["used"] = new_used
    _in_memory_quotas[user_id] = current
    return True


# ==========================================
# User Authentication & Management
# ==========================================

USERS_COLLECTION_NAME = "users"
_in_memory_users: Dict[str, Dict[str, Any]] = {}


def _hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    import hashlib
    import secrets
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return hashed, salt


def create_user(email: str, password: str, full_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Registers a new user. Raises ValueError if email already exists.
    """
    normalized_email = email.strip().lower()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("Invalid email address provided.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")

    hashed_pw, salt = _hash_password(password)
    now = time.time()
    user_doc = {
        "email": normalized_email,
        "full_name": (full_name or "").strip() or normalized_email.split("@")[0],
        "password_hash": hashed_pw,
        "salt": salt,
        "tier": "free",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_timestamp": now,
    }

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            # Ensure unique index on email
            users_col.create_index("email", unique=True)
            existing = users_col.find_one({"email": normalized_email})
            if existing:
                raise ValueError("An account with this email already exists.")
            insert_res = users_col.insert_one(user_doc)
            user_doc["id"] = str(insert_res.inserted_id)
            del user_doc["password_hash"]
            del user_doc["salt"]
            if "_id" in user_doc:
                del user_doc["_id"]
            return user_doc
        except ValueError:
            raise
        except Exception as err:
            logger.error(f"Error inserting user into MongoDB ({err}). Using in-memory.")

    if normalized_email in _in_memory_users:
        raise ValueError("An account with this email already exists.")

    user_doc["id"] = f"user_{int(now * 1000)}"
    _in_memory_users[normalized_email] = user_doc

    safe_user = {k: v for k, v in user_doc.items() if k not in ("password_hash", "salt", "_id")}
    return safe_user


def get_or_create_google_user(email: str, full_name: Optional[str] = None, avatar_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Finds or provisions an account for a Google-authenticated user in MongoDB.
    """
    normalized_email = email.strip().lower()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("Invalid Google account email.")

    now = time.time()
    name = (full_name or "").strip() or normalized_email.split("@")[0]

    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            existing = users_col.find_one({"email": normalized_email})
            if existing:
                return {
                    "id": str(existing.get("_id", existing.get("id"))),
                    "email": existing.get("email"),
                    "full_name": existing.get("full_name"),
                    "avatar_url": existing.get("avatar_url", avatar_url),
                    "provider": "google",
                    "tier": existing.get("tier", "free"),
                    "created_at": existing.get("created_at"),
                }

            # New Google User
            new_doc = {
                "email": normalized_email,
                "full_name": name,
                "avatar_url": avatar_url,
                "provider": "google",
                "tier": "free",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_timestamp": now,
            }
            insert_res = users_col.insert_one(new_doc)
            new_doc["id"] = str(insert_res.inserted_id)
            if "_id" in new_doc:
                del new_doc["_id"]
            return new_doc
        except Exception as err:
            logger.error(f"Error provisioning Google user in MongoDB: {err}")

    # In-memory fallback
    if normalized_email in _in_memory_users:
        u = _in_memory_users[normalized_email]
        return {
            "id": str(u.get("id")),
            "email": u.get("email"),
            "full_name": u.get("full_name"),
            "avatar_url": u.get("avatar_url", avatar_url),
            "provider": "google",
            "tier": u.get("tier", "free"),
            "created_at": u.get("created_at"),
        }

    user_doc = {
        "id": f"guser_{int(now * 1000)}",
        "email": normalized_email,
        "full_name": name,
        "avatar_url": avatar_url,
        "provider": "google",
        "tier": "free",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_timestamp": now,
    }
    _in_memory_users[normalized_email] = user_doc
    return user_doc


def authenticate_user(email: str, password: str) -> Dict[str, Any]:
    """
    Authenticates a user by email and password. Returns safe user dictionary.
    """
    normalized_email = email.strip().lower()
    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            user = users_col.find_one({"email": normalized_email})
            if user:
                hashed, _ = _hash_password(password, user.get("salt", ""))
                if hashed == user.get("password_hash"):
                    user_info = {
                        "id": str(user.get("_id", user.get("id"))),
                        "email": user.get("email"),
                        "full_name": user.get("full_name"),
                        "tier": user.get("tier", "free"),
                        "created_at": user.get("created_at"),
                    }
                    return user_info
        except Exception as err:
            logger.error(f"MongoDB authentication failed ({err}). Trying memory.")

    user = _in_memory_users.get(normalized_email)
    if user:
        hashed, _ = _hash_password(password, user.get("salt", ""))
        if hashed == user.get("password_hash"):
            return {
                "id": str(user.get("id")),
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "tier": user.get("tier", "free"),
                "created_at": user.get("created_at"),
            }

    raise ValueError("Invalid email or password.")


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves user profile information by user ID.
    """
    collection = get_db()
    if collection is not None and _db is not None:
        try:
            from bson.objectid import ObjectId
            users_col = _db[USERS_COLLECTION_NAME]
            query = {}
            if ObjectId.is_valid(user_id):
                query = {"_id": ObjectId(user_id)}
            else:
                query = {"id": user_id}
            user = users_col.find_one(query)
            if user:
                return {
                    "id": str(user.get("_id", user.get("id"))),
                    "email": user.get("email"),
                    "full_name": user.get("full_name"),
                    "tier": user.get("tier", "free"),
                    "created_at": user.get("created_at"),
                }
        except Exception as err:
            logger.error(f"Error fetching user by ID ({err})")

    for u in _in_memory_users.values():
        if u.get("id") == user_id:
            return {
                "id": u.get("id"),
                "email": u.get("email"),
                "full_name": u.get("full_name"),
                "tier": u.get("tier", "free"),
                "created_at": u.get("created_at"),
            }
    return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves safe user profile by email address.
    """
    normalized_email = email.strip().lower()
    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            user = users_col.find_one({"email": normalized_email})
            if user:
                return {
                    "id": str(user.get("_id", user.get("id"))),
                    "email": user.get("email"),
                    "full_name": user.get("full_name"),
                    "tier": user.get("tier", "free"),
                    "created_at": user.get("created_at"),
                }
        except Exception as err:
            logger.error(f"Error fetching user by email ({err})")

    user = _in_memory_users.get(normalized_email)
    if user:
        return {
            "id": user.get("id"),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "tier": user.get("tier", "free"),
            "created_at": user.get("created_at"),
        }
    return None


def update_user_tier(email: str, new_tier: str) -> bool:
    """
    Updates the tier (free, pro, enterprise) of a user in MongoDB.
    """
    normalized_email = email.strip().lower()
    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            res = users_col.update_one(
                {"email": normalized_email},
                {"$set": {"tier": new_tier, "tier_updated_at": datetime.now(timezone.utc).isoformat()}}
            )
            return res.modified_count > 0 or res.matched_count > 0
        except Exception as err:
            logger.error(f"Error updating user tier ({err})")

    if normalized_email in _in_memory_users:
        _in_memory_users[normalized_email]["tier"] = new_tier
        return True
    return False


def get_all_users(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves user list for administration.
    """
    collection = get_db()
    if collection is not None and _db is not None:
        try:
            users_col = _db[USERS_COLLECTION_NAME]
            cursor = users_col.find(
                {},
                {"password_hash": 0, "salt": 0}
            ).limit(limit)
            results = []
            for doc in cursor:
                doc["id"] = str(doc.get("_id", doc.get("id")))
                if "_id" in doc:
                    del doc["_id"]
                results.append(doc)
            return results
        except Exception as err:
            logger.error(f"Error listing users from MongoDB ({err})")

    return [
        {k: v for k, v in u.items() if k not in ("password_hash", "salt", "_id")}
        for u in list(_in_memory_users.values())[:limit]
    ]


