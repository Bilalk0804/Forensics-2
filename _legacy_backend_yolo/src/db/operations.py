import sqlite3
import logging

class DatabaseHandler:
    def __init__(self, db_path):
        self.db_path = db_path
        self.logger = logging.getLogger("SENTINEL_DB")

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_schema(self):
        """Creates the tables based on the architecture agreement."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # TABLE 1: FILES (The Inventory)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                file_hash TEXT,
                file_size INTEGER,
                mime_type TEXT,
                processed_status TEXT DEFAULT 'PENDING'
            )
        ''')
        
        # TABLE 2: ARTIFACTS (The Evidence)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                pipeline_name TEXT,
                risk_level TEXT, -- 'HIGH', 'MEDIUM', 'LOW'
                description TEXT,
                metadata JSON,
                FOREIGN KEY(file_id) REFERENCES files(file_id)
            )
        ''')
        
        # TABLE 3: TEXT EVIDENCE (NER, Topics, Keywords)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS text_evidence (
                evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                evidence_type TEXT,  -- 'NER', 'TOPIC', 'KEYWORD'
                entity_type TEXT,
                entity_value TEXT,
                confidence REAL,
                context TEXT,
                risk_level TEXT,  -- 'critical', 'high', 'medium', 'low'
                category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES files(file_id)
            )
        ''')
        
        # Create index for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_text_evidence_risk 
            ON text_evidence(risk_level)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_text_evidence_type 
            ON text_evidence(evidence_type)
        ''')
        
        conn.commit()
        conn.close()
        self.logger.info("Database schema initialized.")

    def clear_files(self):
        """Clear all file records from the database for fresh analysis."""
        conn = self.get_connection()
        try:
            conn.execute('DELETE FROM artifacts')
            conn.execute('DELETE FROM files')
            conn.commit()
            self.logger.info("Database files cleared for new analysis")
        except Exception as e:
            self.logger.error(f"Failed to clear database files: {e}")
        finally:
            conn.close()

    def insert_file(self, path, file_hash, size, mime):
        """Used by Ingestor to add a file to the queue."""
        conn = self.get_connection()
        try:
            conn.execute('''
                INSERT OR IGNORE INTO files (file_path, file_hash, file_size, mime_type)
                VALUES (?, ?, ?, ?)
            ''', (path, file_hash, size, mime))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to insert file {path}: {e}")
        finally:
            conn.close()

    def insert_text_evidence(self, file_id, evidence_type, entity_type, 
                              entity_value, confidence, context, risk_level, category):
        """Insert text evidence record."""
        conn = self.get_connection()
        try:
            conn.execute('''
                INSERT INTO text_evidence 
                (file_id, evidence_type, entity_type, entity_value, confidence, context, risk_level, category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (file_id, evidence_type, entity_type, entity_value, 
                  confidence, context, risk_level, category))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to insert text evidence: {e}")
        finally:
            conn.close()

    def get_text_files(self, status='PENDING'):
        """Get files pending text analysis."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_id, file_path, mime_type 
                FROM files 
                WHERE processed_status = ? 
                AND (mime_type LIKE 'text/%' OR mime_type LIKE 'application/pdf%')
            ''', (status,))
            rows = cursor.fetchall()
            return [{'file_id': r[0], 'file_path': r[1], 'mime_type': r[2]} for r in rows]
        except Exception as e:
            self.logger.error(f"Failed to get text files: {e}")
            return []
        finally:
            conn.close()

    def get_high_risk_evidence(self, risk_levels=('critical', 'high')):
        """Get all high-risk text evidence for reporting."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(risk_levels))
            cursor.execute(f'''
                SELECT te.*, f.file_path 
                FROM text_evidence te
                JOIN files f ON te.file_id = f.file_id
                WHERE te.risk_level IN ({placeholders})
                ORDER BY 
                    CASE te.risk_level 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                    END,
                    te.created_at DESC
            ''', risk_levels)
            return cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get high risk evidence: {e}")
            return []
        finally:
            conn.close()

    def get_files_by_mime(self, mime_pattern):
        """
        Retrieve pending files matching a MIME-type pattern.

        Args:
            mime_pattern: SQL LIKE pattern, e.g. 'image/%'

        Returns:
            List of tuples (file_id, file_path, mime_type)
        """
        conn = self.get_connection()
        try:
            cursor = conn.execute('''
                SELECT file_id, file_path, mime_type
                FROM files
                WHERE mime_type LIKE ? AND processed_status = 'PENDING'
            ''', (mime_pattern,))
            return cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to query files with pattern {mime_pattern}: {e}")
            return []
        finally:
            conn.close()

    def insert_artifact(self, file_id, pipeline_name, risk_level, description, metadata):
        """
        Insert an analysis artifact into the artifacts table.

        Args:
            file_id: FK reference to the files table
            pipeline_name: Name of the pipeline that produced the artifact
            risk_level: 'HIGH', 'MEDIUM', or 'LOW'
            description: Human-readable description of the finding
            metadata: JSON-serializable string with detailed data
        """
        conn = self.get_connection()
        try:
            conn.execute('''
                INSERT INTO artifacts (file_id, pipeline_name, risk_level, description, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_id, pipeline_name, risk_level, description, metadata))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to insert artifact for file_id {file_id}: {e}")
        finally:
            conn.close()

    def update_file_status(self, file_id, status):
        """
        Update the processing status of a file.

        Args:
            file_id: ID of the file to update
            status: New status string, e.g. 'PROCESSED', 'ERROR'
        """
        conn = self.get_connection()
        try:
            conn.execute('''
                UPDATE files SET processed_status = ? WHERE file_id = ?
            ''', (status, file_id))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to update status for file_id {file_id}: {e}")
        finally:
            conn.close()

    def count_files(self, search=None, risk=None, mime=None) -> int:
        """Return total number of files indexed with optional filters."""
        conn = self.get_connection()
        where_clauses = []
        params = []

        if search:
            where_clauses.append("f.file_path LIKE ?")
            params.append(f"%{search}%")
        if mime:
            where_clauses.append("f.mime_type LIKE ?")
            params.append(f"{mime}%")

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        risk_rank_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        risk_rank = risk_rank_map.get(risk.upper()) if risk else None

        query = f"""
            SELECT COUNT(*)
            FROM (
                SELECT
                    f.file_id,
                    MAX(CASE a.risk_level
                        WHEN 'HIGH' THEN 3
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW' THEN 1
                        ELSE 0
                    END) AS risk_rank
                FROM files f
                LEFT JOIN artifacts a ON a.file_id = f.file_id
                {where_sql}
                GROUP BY f.file_id
                {"HAVING risk_rank = ?" if risk_rank is not None else ""}
            ) sub
        """
        if risk_rank is not None:
            params.append(risk_rank)

        try:
            cursor = conn.execute(query, params)
            return int(cursor.fetchone()[0])
        except Exception as e:
            self.logger.error(f"Failed to count files: {e}")
            return 0
        finally:
            conn.close()

    def list_files_with_risk(self, limit=200, offset=0, search=None, risk=None, mime=None):
        """List files with artifact count and highest risk level."""
        conn = self.get_connection()
        where_clauses = []
        params = []

        if search:
            where_clauses.append("f.file_path LIKE ?")
            params.append(f"%{search}%")
        if mime:
            where_clauses.append("f.mime_type LIKE ?")
            params.append(f"{mime}%")

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        risk_rank_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        risk_rank = risk_rank_map.get(risk.upper()) if risk else None

        query = f"""
            SELECT
                f.file_id,
                f.file_path,
                f.file_hash,
                f.file_size,
                f.mime_type,
                f.processed_status,
                COUNT(a.artifact_id) AS artifact_count,
                MAX(CASE a.risk_level
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END) AS risk_rank
            FROM files f
            LEFT JOIN artifacts a ON a.file_id = f.file_id
            {where_sql}
            GROUP BY f.file_id
            {"HAVING risk_rank = ?" if risk_rank is not None else ""}
            ORDER BY f.file_id
            LIMIT ? OFFSET ?
        """

        if risk_rank is not None:
            params.append(risk_rank)
        params.extend([limit, offset])

        try:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to list files: {e}")
            return []
        finally:
            conn.close()

        def rank_to_risk(rank):
            if rank == 3:
                return "HIGH"
            if rank == 2:
                return "MEDIUM"
            if rank == 1:
                return "LOW"
            return "NONE"

        results = []
        for row in rows:
            (
                file_id,
                file_path,
                file_hash,
                file_size,
                mime_type,
                processed_status,
                artifact_count,
                risk_rank_value,
            ) = row
            results.append(
                {
                    "file_id": file_id,
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "processed_status": processed_status,
                    "artifact_count": artifact_count,
                    "risk_level": rank_to_risk(risk_rank_value or 0),
                }
            )
        return results

    def list_all_files_with_risk(self):
        """List all files with artifact count and highest risk level."""
        conn = self.get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT
                    f.file_id,
                    f.file_path,
                    f.file_hash,
                    f.file_size,
                    f.mime_type,
                    f.processed_status,
                    COUNT(a.artifact_id) AS artifact_count,
                    MAX(CASE a.risk_level
                        WHEN 'HIGH' THEN 3
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW' THEN 1
                        ELSE 0
                    END) AS risk_rank
                FROM files f
                LEFT JOIN artifacts a ON a.file_id = f.file_id
                GROUP BY f.file_id
                ORDER BY f.file_id
                """
            )
            rows = cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to list all files: {e}")
            return []
        finally:
            conn.close()

        def rank_to_risk(rank):
            if rank == 3:
                return "HIGH"
            if rank == 2:
                return "MEDIUM"
            if rank == 1:
                return "LOW"
            return "NONE"

        results = []
        for row in rows:
            (
                file_id,
                file_path,
                file_hash,
                file_size,
                mime_type,
                processed_status,
                artifact_count,
                risk_rank,
            ) = row
            results.append(
                {
                    "file_id": file_id,
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "processed_status": processed_status,
                    "artifact_count": artifact_count,
                    "risk_level": rank_to_risk(risk_rank or 0),
                }
            )
        return results