package trustscore

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteAudit implements AuditBackend with WAL mode and serialized writers.
type SQLiteAudit struct {
	db *sql.DB
}

// NewSQLiteAudit opens the audit database with WAL mode and single-writer serialization.
func NewSQLiteAudit(dbPath string) (*SQLiteAudit, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	db.SetMaxIdleConns(1)

	audit := &SQLiteAudit{db: db}
	if err := audit.migrate(); err != nil {
		return nil, err
	}

	return audit, nil
}

func (a *SQLiteAudit) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tier1_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id TEXT NOT NULL UNIQUE,
		event_json TEXT NOT NULL,
		lgbm_prob REAL NOT NULL,
		tier0_decision TEXT NOT NULL,
		tier1_label TEXT,
		tier1_confidence REAL,
		feedback_delta REAL,
		feedback_reason TEXT,
		client_ip TEXT NOT NULL,
		user_id TEXT,
		enqueued_at INTEGER NOT NULL,
		processed_at INTEGER,
		worker_id TEXT,
		status TEXT DEFAULT 'pending',
		error_message TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_status ON tier1_audit(status);
	CREATE INDEX IF NOT EXISTS idx_audit_ip ON tier1_audit(client_ip);
	CREATE INDEX IF NOT EXISTS idx_audit_user ON tier1_audit(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_processed ON tier1_audit(processed_at);
	CREATE INDEX IF NOT EXISTS idx_audit_job ON tier1_audit(job_id);

	CREATE TABLE IF NOT EXISTS tier1_grey_zone_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tier TEXT NOT NULL,
		center REAL NOT NULL,
		width REAL NOT NULL,
		changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := a.db.Exec(schema)
	return err
}

// LogEnqueue records that a job was queued.
func (a *SQLiteAudit) LogEnqueue(job Tier1Job) error {
	eventJSON, _ := json.Marshal(job.Event)

	_, err := a.db.Exec(`
		INSERT INTO tier1_audit (
			job_id, event_json, lgbm_prob, tier0_decision,
			client_ip, user_id, enqueued_at, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
	`, job.ID, eventJSON, job.LGBMProb, job.Tier0Decision,
		job.ClientIP, job.UserID, int64(job.EnqueuedAt))

	return err
}

// LogResult records the outcome of processing.
func (a *SQLiteAudit) LogResult(jobID, workerID string, result Tier1Result, errMsg string) error {
	status := "completed"
	if errMsg != "" {
		status = "failed"
	}

	var label *string
	var confidence *float64
	if errMsg == "" {
		l := result.Label
		c := result.Confidence
		label = &l
		confidence = &c
	}

	_, err := a.db.Exec(`
		UPDATE tier1_audit SET
			tier1_label = ?,
			tier1_confidence = ?,
			processed_at = ?,
			worker_id = ?,
			status = ?,
			error_message = ?
		WHERE job_id = ?
	`, label, confidence, time.Now().Unix(),
		workerID, status, errMsg, jobID)

	return err
}

// LogFeedback records that a trustscore correction was applied.
func (a *SQLiteAudit) LogFeedback(jobID string, delta float64, reason string) error {
	_, err := a.db.Exec(`
		UPDATE tier1_audit SET
			feedback_delta = ?,
			feedback_reason = ?
		WHERE job_id = ?
	`, delta, reason, jobID)

	return err
}

// Close shuts down the database.
func (a *SQLiteAudit) Close() error {
	return a.db.Close()
}
