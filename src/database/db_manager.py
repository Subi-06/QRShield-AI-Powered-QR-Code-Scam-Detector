"""Database manager module for QRShield AI scan history operations.

Provides SQLite-based persistent storage, filtering, querying, and
analytical statistics for QR code security scans and threat assessments.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union
import uuid

try:
    from config.settings import DATABASE_PATH
except ImportError:
    try:
        from src.config.settings import DATABASE_PATH  # type: ignore
    except ImportError:
        DATABASE_PATH = Path("qrshield.db")

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database operations for QRShield AI scan records."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the DatabaseManager.

        Args:
            db_path: Optional filesystem path to the SQLite database file.
                     Defaults to DATABASE_PATH from configuration.
        """
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path(DATABASE_PATH)

        # Ensure target directory exists
        if self.db_path.parent and not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection.

        Returns:
            sqlite3.Connection: Database connection with Row factory enabled.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create required tables and indices if they do not exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            content_type TEXT NOT NULL,
            content_preview TEXT,
            full_content TEXT,
            prediction_category TEXT,
            risk_level TEXT,
            model_probability REAL,
            risk_score REAL,
            risk_indicators TEXT,
            explanation_summary TEXT,
            model_version TEXT,
            features_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
        index_sql = """
        CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_history_content_type ON scan_history(content_type);
        CREATE INDEX IF NOT EXISTS idx_scan_history_risk_level ON scan_history(risk_level);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(create_table_sql)
                cursor.executescript(index_sql)
                conn.commit()
            logger.info("Database initialized successfully at %s", self.db_path)
        except sqlite3.Error as e:
            logger.error("Failed to initialize database at %s: %s", self.db_path, e)
            raise

    def save_scan(self, scan_data: Dict[str, Any]) -> str:
        """Save or update a scan record in the database.

        Generates a unique UUID if scan_id is omitted, stamps current UTC
        timestamp if missing, serializes complex objects, and handles
        duplicate records gracefully.

        Args:
            scan_data: Dictionary containing scan attributes.

        Returns:
            str: The unique scan_id of the persisted scan.
        """
        scan_id = str(scan_data.get("scan_id") or uuid.uuid4())
        timestamp = scan_data.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        content_type = str(scan_data.get("content_type", "unknown"))
        content_preview = scan_data.get("content_preview")
        full_content = scan_data.get("full_content")
        prediction_category = scan_data.get("prediction_category")
        risk_level = scan_data.get("risk_level")

        model_probability = scan_data.get("model_probability")
        if model_probability is not None:
            try:
                model_probability = float(model_probability)
            except (ValueError, TypeError):
                model_probability = None

        risk_score = scan_data.get("risk_score")
        if risk_score is not None:
            try:
                risk_score = float(risk_score)
            except (ValueError, TypeError):
                risk_score = None

        # Serialize risk_indicators
        risk_indicators = scan_data.get("risk_indicators")
        if isinstance(risk_indicators, (dict, list)):
            risk_indicators_str = json.dumps(risk_indicators)
        elif risk_indicators is not None:
            risk_indicators_str = str(risk_indicators)
        else:
            risk_indicators_str = None

        explanation_summary = scan_data.get("explanation_summary")
        model_version = scan_data.get("model_version")

        # Serialize features_json
        features_json = scan_data.get("features_json")
        if isinstance(features_json, (dict, list)):
            features_json_str = json.dumps(features_json)
        elif features_json is not None:
            features_json_str = str(features_json)
        else:
            features_json_str = None

        insert_sql = """
        INSERT INTO scan_history (
            scan_id,
            timestamp,
            content_type,
            content_preview,
            full_content,
            prediction_category,
            risk_level,
            model_probability,
            risk_score,
            risk_indicators,
            explanation_summary,
            model_version,
            features_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id) DO UPDATE SET
            timestamp=excluded.timestamp,
            content_type=excluded.content_type,
            content_preview=excluded.content_preview,
            full_content=excluded.full_content,
            prediction_category=excluded.prediction_category,
            risk_level=excluded.risk_level,
            model_probability=excluded.model_probability,
            risk_score=excluded.risk_score,
            risk_indicators=excluded.risk_indicators,
            explanation_summary=excluded.explanation_summary,
            model_version=excluded.model_version,
            features_json=excluded.features_json;
        """

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    insert_sql,
                    (
                        scan_id,
                        timestamp,
                        content_type,
                        content_preview,
                        full_content,
                        prediction_category,
                        risk_level,
                        model_probability,
                        risk_score,
                        risk_indicators_str,
                        explanation_summary,
                        model_version,
                        features_json_str,
                    ),
                )
                conn.commit()
            logger.info("Scan record successfully saved with scan_id=%s", scan_id)
            return scan_id
        except sqlite3.Error as e:
            logger.error("Error saving scan record with scan_id=%s: %s", scan_id, e)
            raise

    def get_all_scans(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve paginated scan records ordered by timestamp descending.

        Args:
            limit: Maximum number of scan records to return.
            offset: Number of scan records to skip.

        Returns:
            List[Dict[str, Any]]: List of scan records as dictionaries.
        """
        query = """
        SELECT * FROM scan_history
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?;
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (max(0, limit), max(0, offset)))
                rows = cursor.fetchall()
                return [self._dict_from_row(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error fetching scan records: %s", e)
            return []

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single scan record by its unique scan_id.

        Args:
            scan_id: Unique identifier for the scan.

        Returns:
            Optional[Dict[str, Any]]: Scan record dict or None if not found.
        """
        query = "SELECT * FROM scan_history WHERE scan_id = ? LIMIT 1;"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (scan_id,))
                row = cursor.fetchone()
                if row is not None:
                    return self._dict_from_row(row)
                return None
        except sqlite3.Error as e:
            logger.error("Error retrieving scan by id=%s: %s", scan_id, e)
            return None

    def search_scans(self, query: str) -> List[Dict[str, Any]]:
        """Search scans matching query in content_preview or prediction_category.

        Uses parameterized LIKE queries with proper escaping.

        Args:
            query: Substring text to search.

        Returns:
            List[Dict[str, Any]]: Matching scan records ordered by timestamp descending.
        """
        if not query:
            return self.get_all_scans()

        # Escape special SQL LIKE wildcards in user query
        escaped_query = (
            query.replace("/", "//")
            .replace("%", "/%")
            .replace("_", "/_")
        )
        search_pattern = f"%{escaped_query}%"

        sql = """
        SELECT * FROM scan_history
        WHERE content_preview LIKE ? ESCAPE '/'
           OR prediction_category LIKE ? ESCAPE '/'
        ORDER BY timestamp DESC;
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (search_pattern, search_pattern))
                rows = cursor.fetchall()
                return [self._dict_from_row(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error executing search for '%s': %s", query, e)
            return []

    def filter_scans(
        self,
        content_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Filter scans dynamically by content type, risk level, or date range.

        Args:
            content_type: Optional content type filter (e.g. 'URL', 'UPI').
            risk_level: Optional risk level filter (e.g. 'LOW', 'MEDIUM', 'HIGH').
            start_date: Optional inclusive start date/time (ISO string).
            end_date: Optional inclusive end date/time (ISO string).

        Returns:
            List[Dict[str, Any]]: Filtered scan records ordered by timestamp descending.
        """
        conditions: List[str] = []
        params: List[Any] = []

        if content_type:
            conditions.append("content_type = ?")
            params.append(content_type)

        if risk_level:
            conditions.append("risk_level = ?")
            params.append(risk_level)

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date)

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
        SELECT * FROM scan_history
        {where_clause}
        ORDER BY timestamp DESC;
        """

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params))
                rows = cursor.fetchall()
                return [self._dict_from_row(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error filtering scans: %s", e)
            return []

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record by scan_id.

        Args:
            scan_id: Unique identifier for the scan.

        Returns:
            bool: True if a record was deleted, False otherwise.
        """
        sql = "DELETE FROM scan_history WHERE scan_id = ?;"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (scan_id,))
                conn.commit()
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info("Deleted scan record id=%s", scan_id)
                else:
                    logger.warning("No scan record found to delete with id=%s", scan_id)
                return deleted
        except sqlite3.Error as e:
            logger.error("Error deleting scan record id=%s: %s", scan_id, e)
            return False

    def clear_history(self) -> int:
        """Delete all scan records from the database.

        Returns:
            int: Number of deleted records.
        """
        sql = "DELETE FROM scan_history;"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql)
                conn.commit()
                count = cursor.rowcount
                logger.info("Cleared scan history (%d records deleted)", count)
                return count
        except sqlite3.Error as e:
            logger.error("Error clearing scan history: %s", e)
            return 0

    def get_daily_scan_counts(self, days: int = 30) -> List[Dict[str, Any]]:
        """Return scan counts per calendar day for the last N days.

        Guarantees that all days in the requested window are included,
        defaulting count to 0 on days without scans.

        Args:
            days: Number of past days to compute counts for (default: 30).

        Returns:
            List[Dict[str, Any]]: Chronologically sorted list of dicts with
                                  'date' (YYYY-MM-DD) and 'count' (int).
        """
        now = datetime.now(timezone.utc)
        # Prepopulate zero counts for each day in range
        daily_map: Dict[str, int] = {}
        for i in range(days - 1, -1, -1):
            date_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            daily_map[date_str] = 0

        start_date_str = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        sql = """
        SELECT substr(timestamp, 1, 10) AS scan_date, COUNT(*) AS count
        FROM scan_history
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY scan_date
        ORDER BY scan_date ASC;
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (start_date_str,))
                rows = cursor.fetchall()
                for row in rows:
                    date_key = row["scan_date"]
                    if date_key in daily_map:
                        daily_map[date_key] = int(row["count"])
        except sqlite3.Error as e:
            logger.error("Error aggregating daily scan counts: %s", e)

        return [{"date": d, "count": c} for d, c in daily_map.items()]

    def get_statistics(self) -> Dict[str, Any]:
        """Aggregate summary statistics across all scans in history.

        Returns:
            Dict[str, Any]: Aggregated dictionary containing:
                - 'total_scans': int
                - 'scans_by_risk_level': Dict[str, int]
                - 'scans_by_content_type': Dict[str, int]
                - 'scans_by_date': Dict[str, int] (last 30 days)
                - 'recent_scans': List[Dict[str, Any]] (last 10 scans)
        """
        stats: Dict[str, Any] = {
            "total_scans": 0,
            "scans_by_risk_level": {},
            "scans_by_content_type": {},
            "scans_by_date": {},
            "recent_scans": [],
        }

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Total count
                cursor.execute("SELECT COUNT(*) AS total FROM scan_history;")
                total_row = cursor.fetchone()
                stats["total_scans"] = int(total_row["total"]) if total_row else 0

                # Scans grouped by risk level
                cursor.execute(
                    """
                    SELECT COALESCE(risk_level, 'UNKNOWN') AS r_level, COUNT(*) AS count
                    FROM scan_history
                    GROUP BY r_level;
                    """
                )
                stats["scans_by_risk_level"] = {
                    row["r_level"]: int(row["count"]) for row in cursor.fetchall()
                }

                # Scans grouped by content type
                cursor.execute(
                    """
                    SELECT COALESCE(content_type, 'UNKNOWN') AS c_type, COUNT(*) AS count
                    FROM scan_history
                    GROUP BY c_type;
                    """
                )
                stats["scans_by_content_type"] = {
                    row["c_type"]: int(row["count"]) for row in cursor.fetchall()
                }

            # Daily scan counts for the last 30 days
            daily_list = self.get_daily_scan_counts(days=30)
            stats["scans_by_date"] = {item["date"]: item["count"] for item in daily_list}

            # Recent 10 scans
            stats["recent_scans"] = self.get_all_scans(limit=10, offset=0)

        except sqlite3.Error as e:
            logger.error("Error compiling database statistics: %s", e)

        return stats

    def _dict_from_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a sqlite3.Row instance into a dictionary with parsed JSON fields.

        Args:
            row: SQLite Row object.

        Returns:
            Dict[str, Any]: Scan record dictionary with deserialized objects.
        """
        row_dict = dict(row)

        # Deserialize risk_indicators if present as JSON string
        raw_indicators = row_dict.get("risk_indicators")
        if isinstance(raw_indicators, str):
            try:
                row_dict["risk_indicators"] = json.loads(raw_indicators)
            except (json.JSONDecodeError, TypeError):
                row_dict["risk_indicators"] = raw_indicators

        # Deserialize features_json if present as JSON string
        raw_features = row_dict.get("features_json")
        if isinstance(raw_features, str):
            try:
                row_dict["features_json"] = json.loads(raw_features)
            except (json.JSONDecodeError, TypeError):
                row_dict["features_json"] = raw_features

        return row_dict
