package db

import (
	// Using a more direct ECDH type
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"golang.org/x/crypto/bcrypt"
)

const dbFile = "./gowhisper.db"

var DB *sql.DB

type User struct {
	Username      string
	PasswordHash  string
	ECDHPublicKey []byte // Store the marshaled public key
}

func InitDB() error {
	var err error
	// Check if DB file exists, create if not
	_, statErr := os.Stat(dbFile)
	createSchema := os.IsNotExist(statErr)

	DB, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		return err
	}

	if createSchema {
		log.Println("Database file not found, creating schema...")
		schema := `
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            ecdh_public_key BLOB NOT NULL
        );
        `
		_, err = DB.Exec(schema)
		if err != nil {
			return err
		}
		log.Println("Database schema created.")
	}
	return nil
}

func RegisterUser(username, password string, ecdhPublicKey []byte) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	stmt, err := DB.Prepare("INSERT INTO users(username, password_hash, ecdh_public_key) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, string(hashedPassword), ecdhPublicKey)
	return err
}

func AuthenticateUser(username, password string) (*User, error) {
	user := &User{Username: username}
	var ecdhPubKeyBytes []byte // Temporary variable to scan BLOB

	err := DB.QueryRow("SELECT password_hash, ecdh_public_key FROM users WHERE username = ?", username).Scan(&user.PasswordHash, &ecdhPubKeyBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err // Other DB error
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// Password does not match
		return nil, nil
	}

	user.ECDHPublicKey = ecdhPubKeyBytes
	return user, nil
}

func GetUserPublicKey(username string) ([]byte, error) {
	var pubKeyBytes []byte
	err := DB.QueryRow("SELECT ecdh_public_key FROM users WHERE username = ?", username).Scan(&pubKeyBytes)
	if err != nil {
		// If err is sql.ErrNoRows, return it directly.
		// pubKeyBytes will be its zero value (nil for a slice) in this case.
		// For other errors, also return them.
		return nil, err
	}
	// No error, user found, pubKeyBytes is populated.
	return pubKeyBytes, nil
}
