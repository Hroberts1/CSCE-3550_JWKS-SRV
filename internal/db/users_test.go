package db

import (
	"testing"
)

func TestUsersTableCreation(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Verify users table exists by trying to insert a record
	query := `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`
	_, err := db.conn.Exec(query, "testuser", "hashed_password_123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to insert into users table: %v", err)
	}

	// Verify the record was inserted
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "testuser").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query users table: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 user record, got %d", count)
	}
}

func TestUsersTableSchema(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Query table schema
	rows, err := db.conn.Query("PRAGMA table_info(users)")
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
	expectedColumns := []string{"id", "username", "password_hash", "email", "date_registered", "last_login"}
	for _, col := range expectedColumns {
		if !columns[col] {
			t.Errorf("Expected column %s not found in users table", col)
		}
	}
}

func TestUsersTableConstraints(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Test unique username constraint
	query := `INSERT INTO users (username, password_hash) VALUES (?, ?)`
	_, err := db.conn.Exec(query, "uniqueuser", "hash1")
	if err != nil {
		t.Fatalf("Failed to insert first user: %v", err)
	}

	// Try to insert duplicate username - should fail
	_, err = db.conn.Exec(query, "uniqueuser", "hash2")
	if err == nil {
		t.Error("Expected unique constraint violation for duplicate username")
	}

	// Test unique email constraint
	query = `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`
	_, err = db.conn.Exec(query, "user1", "hash1", "unique@example.com")
	if err != nil {
		t.Fatalf("Failed to insert user with email: %v", err)
	}

	// Try to insert duplicate email - should fail
	_, err = db.conn.Exec(query, "user2", "hash2", "unique@example.com")
	if err == nil {
		t.Error("Expected unique constraint violation for duplicate email")
	}
}
