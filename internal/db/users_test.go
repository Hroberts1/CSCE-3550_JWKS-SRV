package db

import (
	"strings"
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

func TestCreateUser(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Test user creation
	username := "testuser"
	email := "test@example.com"

	password, err := db.CreateUser(username, email)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Verify password is UUIDv4 format (36 characters)
	if len(password) != 36 {
		t.Errorf("Expected password length 36, got %d", len(password))
	}

	// Verify user exists in database
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? AND email = ?", 
		username, email).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query user: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 user record, got %d", count)
	}

	// Verify password is hashed (not stored in plain text)
	var storedHash string
	err = db.conn.QueryRow("SELECT password_hash FROM users WHERE username = ?", 
		username).Scan(&storedHash)
	if err != nil {
		t.Fatalf("Failed to get password hash: %v", err)
	}

	if storedHash == password {
		t.Error("Password should be hashed, not stored in plain text")
	}

	// Verify hash format (should be base64:base64)
	parts := strings.Split(storedHash, ":")
	if len(parts) != 2 {
		t.Errorf("Expected hash format 'salt:hash', got %s", storedHash)
	}
}

func TestVerifyPassword(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Create test user
	username := "verifyuser"
	email := "verify@example.com"

	password, err := db.CreateUser(username, email)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test correct password verification
	valid, err := db.VerifyPassword(username, password)
	if err != nil {
		t.Fatalf("Failed to verify password: %v", err)
	}

	if !valid {
		t.Error("Expected password to be valid")
	}

	// Test incorrect password verification
	valid, err = db.VerifyPassword(username, "wrongpassword")
	if err != nil {
		t.Fatalf("Failed to verify wrong password: %v", err)
	}

	if valid {
		t.Error("Expected wrong password to be invalid")
	}

	// Test non-existent user
	_, err = db.VerifyPassword("nonexistent", password)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

func TestGetUserByUsername(t *testing.T) {
	// Create test database
	db, _ := testDatabase(t)
	defer db.Close()

	// Create test user
	username := "getuser"
	email := "get@example.com"

	_, err := db.CreateUser(username, email)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Get user by username
	user, err := db.GetUserByUsername(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	// Verify user data
	if user.Username != username {
		t.Errorf("Expected username %s, got %s", username, user.Username)
	}

	if user.Email != email {
		t.Errorf("Expected email %s, got %s", email, user.Email)
	}

	if user.ID == 0 {
		t.Error("Expected non-zero user ID")
	}

	if user.PasswordHash == "" {
		t.Error("Expected non-empty password hash")
	}

	// Test non-existent user
	_, err = db.GetUserByUsername("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}
