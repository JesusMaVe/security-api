package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ciphertext TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func insertRecord(db *sql.DB, ciphertext string) (int64, error) {
	res, err := db.Exec(`INSERT INTO records (ciphertext) VALUES (?)`, ciphertext)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func latestRecord(db *sql.DB) (string, error) {
	var ciphertext string
	err := db.QueryRow(`SELECT ciphertext FROM records ORDER BY id DESC LIMIT 1`).Scan(&ciphertext)
	return ciphertext, err
}
