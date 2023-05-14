package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

var key = []byte{ // Remember to change your key!
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

type Entry struct {
	ID          string  `json:"id"`
	Date        string  `json:"date"`
	Description string  `json:"description"`
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./diary.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	create table if not exists entries (id text not null primary key, date text, description text);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}

	http.HandleFunc("/entries", entriesHandler)
	http.HandleFunc("/entries/", entryHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func entriesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case http.MethodGet:
			getEntries(w, r)
		case http.MethodPost:
			createEntry(w, r)
		default:
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func entryHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getEntry(w, r)
	case http.MethodPut:
		updateEntry(w, r)
	case http.MethodDelete:
		deleteEntry(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func updateEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/entries/")
	var entry Entry
	err := json.NewDecoder(r.Body).Decode(&entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if entry.Date == "" || entry.Description == "" {
		http.Error(w, "Missing field(s)", http.StatusBadRequest)
		return
	}
	encryptedDescription, err := encrypt(entry.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("update entries set date = ?, description = ? where id = ?", entry.Date, encryptedDescription, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	decryptedDescription, err := decrypt(encryptedDescription)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entry.Description = decryptedDescription
	json.NewEncoder(w).Encode(entry)
}


func createEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var entry Entry
	err := json.NewDecoder(r.Body).Decode(&entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if entry.ID == "" || entry.Date == "" || entry.Description == "" {
		http.Error(w, "Missing field(s)", http.StatusBadRequest)
		return
	}
	encryptedDescription, err := encrypt(entry.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("insert into entries (id, date, description) values (?, ?, ?)", entry.ID, entry.Date, encryptedDescription)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(entry)
}

func getEntries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("select id, date, description from entries")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var entries []Entry
	for rows.Next() {
		var entry Entry
		err = rows.Scan(&entry.ID, &entry.Date, &entry.Description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		decryptedDescription, err := decrypt(entry.Description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		entry.Description = decryptedDescription	
		entries = append(entries, entry)
	}
	err = rows.Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(entries)
}

func getEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/entries/")
	row := db.QueryRow("select id, date, description from entries where id = ?", id)
	var entry Entry
	err := row.Scan(&entry.ID, &entry.Date, &entry.Description)
	if err == sql.ErrNoRows {
		http.Error(w, "Entry not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Decrypt the description before sending it back to the client
	decryptedDescription, err := decrypt(entry.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entry.Description = decryptedDescription

	json.NewEncoder(w).Encode(entry)
}

func deleteEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/entries/")
	_, err := db.Exec("delete from entries where id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(struct{ Status string }{"Deleted"})
}

func encrypt(text string) (string, error) {
	plaintext := []byte(text)

	// Padding
	padlen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padlen)}, padlen)
	plaintext = append(plaintext, padtext...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plaintext))
	iv := key[:aes.BlockSize] // Use the first 16 bytes of the key as the IV
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(cryptoText string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	iv := key[:aes.BlockSize] // Use the first 16 bytes of the key as the IV
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Unpadding
	unpadding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:(len(plaintext) - unpadding)]

	return string(plaintext), nil
}