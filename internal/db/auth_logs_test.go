package db

import (
	"testing"
	"time"
)

func TestAuthLogsTableCreation(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Verify auth_logs table exists by trying to insert a record
	query := `INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`
	_, err := db.conn.Exec(query, "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Failed to insert into auth_logs table: %v", err)
	}

	// Verify the record was inserted
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM auth_logs WHERE request_ip = ?", "192.168.1.1").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query auth_logs table: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 auth_log record, got %d", count)
	}
}

func TestAuthLogsTableSchema(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Query table schema
	rows, err := db.conn.Query("PRAGMA table_info(auth_logs)")
	if err != nil {
		t.Fatalf("Failed to get table info: %v", err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, datatype string
		var notnull, pk int
		var dfltValue interface{}

		err = rows.Scan(&cid, &name, &datatype, &notnull, &dfltValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		columns[name] = true
	}

	// Check required columns exist
	expectedColumns := []string{"id", "request_ip", "request_timestamp", "user_id"}
	for _, col := range expectedColumns {
		if !columns[col] {
			t.Errorf("Expected column %s not found in auth_logs table", col)
		}
	}
}

func TestLogAuthRequest(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Create a test user first
	username := "testuser"
	email := "test@example.com"
	_, err := db.CreateUser(username, email)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Log auth request with username
	requestIP := "192.168.1.100"
	err = db.LogAuthRequest(requestIP, username)
	if err != nil {
		t.Fatalf("Failed to log auth request: %v", err)
	}

	// Verify log was created
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM auth_logs WHERE request_ip = ?", requestIP).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query auth logs: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 auth log, got %d", count)
	}

	// Verify user_id is set correctly
	user, err := db.GetUserByUsername(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	var loggedUserID *int64
	err = db.conn.QueryRow("SELECT user_id FROM auth_logs WHERE request_ip = ?", requestIP).Scan(&loggedUserID)
	if err != nil {
		t.Fatalf("Failed to query user_id from auth logs: %v", err)
	}

	if loggedUserID == nil {
		t.Error("Expected user_id to be set, got NULL")
	} else if *loggedUserID != user.ID {
		t.Errorf("Expected user_id %d, got %d", user.ID, *loggedUserID)
	}
}

func TestLogAuthRequestWithoutUser(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Log auth request without username
	requestIP := "192.168.1.200"
	err := db.LogAuthRequest(requestIP, "")
	if err != nil {
		t.Fatalf("Failed to log auth request: %v", err)
	}

	// Verify log was created with NULL user_id
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM auth_logs WHERE request_ip = ? AND user_id IS NULL", requestIP).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query auth logs: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 auth log with NULL user_id, got %d", count)
	}
}

func TestLogAuthRequestWithNonexistentUser(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Log auth request with nonexistent username
	requestIP := "192.168.1.300"
	err := db.LogAuthRequest(requestIP, "nonexistent")
	if err != nil {
		t.Fatalf("Failed to log auth request: %v", err)
	}

	// Verify log was created with NULL user_id
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM auth_logs WHERE request_ip = ? AND user_id IS NULL", requestIP).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query auth logs: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 auth log with NULL user_id for nonexistent user, got %d", count)
	}
}

func TestGetAuthLogs(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Create test users
	_, _ = db.CreateUser("user1", "user1@example.com")
	_, _ = db.CreateUser("user2", "user2@example.com")

	// Log multiple auth requests
	testLogs := []struct {
		ip       string
		username string
	}{
		{"192.168.1.1", "user1"},
		{"192.168.1.2", "user2"},
		{"192.168.1.3", ""},
		{"192.168.1.4", "user1"},
	}

	for _, log := range testLogs {
		err := db.LogAuthRequest(log.ip, log.username)
		if err != nil {
			t.Fatalf("Failed to log auth request: %v", err)
		}
	}

	// Retrieve all logs
	logs, err := db.GetAuthLogs(0)
	if err != nil {
		t.Fatalf("Failed to get auth logs: %v", err)
	}

	if len(logs) != len(testLogs) {
		t.Errorf("Expected %d logs, got %d", len(testLogs), len(logs))
	}

	// Verify logs contain expected data
	ipFound := make(map[string]bool)
	for _, log := range logs {
		ipFound[log.RequestIP] = true

		// Verify timestamp is recent
		if time.Since(log.RequestTimestamp) > time.Minute {
			t.Errorf("Log timestamp is too old: %v", log.RequestTimestamp)
		}
	}

	// Check all IPs were logged
	for _, testLog := range testLogs {
		if !ipFound[testLog.ip] {
			t.Errorf("IP %s not found in logs", testLog.ip)
		}
	}
}

func TestGetAuthLogsWithLimit(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Log multiple auth requests
	for i := 0; i < 10; i++ {
		err := db.LogAuthRequest("192.168.1.1", "")
		if err != nil {
			t.Fatalf("Failed to log auth request: %v", err)
		}
	}

	// Retrieve with limit
	limit := 5
	logs, err := db.GetAuthLogs(limit)
	if err != nil {
		t.Fatalf("Failed to get auth logs: %v", err)
	}

	if len(logs) != limit {
		t.Errorf("Expected %d logs, got %d", limit, len(logs))
	}
}

func TestAuthLogsForeignKeyConstraint(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Create a user
	username := "testuser"
	_, err := db.CreateUser(username, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	user, err := db.GetUserByUsername(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	// Log auth request for the user
	err = db.LogAuthRequest("192.168.1.1", username)
	if err != nil {
		t.Fatalf("Failed to log auth request: %v", err)
	}

	// Verify the foreign key relationship
	var loggedUserID int64
	err = db.conn.QueryRow("SELECT user_id FROM auth_logs WHERE request_ip = ?", "192.168.1.1").Scan(&loggedUserID)
	if err != nil {
		t.Fatalf("Failed to query user_id: %v", err)
	}

	if loggedUserID != user.ID {
		t.Errorf("Expected user_id %d, got %d", user.ID, loggedUserID)
	}

	// Verify we can join with users table
	var joinedUsername string
	query := `SELECT u.username FROM auth_logs al 
			  JOIN users u ON al.user_id = u.id 
			  WHERE al.request_ip = ?`
	err = db.conn.QueryRow(query, "192.168.1.1").Scan(&joinedUsername)
	if err != nil {
		t.Fatalf("Failed to join auth_logs with users: %v", err)
	}

	if joinedUsername != username {
		t.Errorf("Expected username %s, got %s", username, joinedUsername)
	}
}
