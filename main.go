package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"

	"github.com/joho/godotenv"
)

type UserData struct {
	Name      string `json:"name"`
	Extension string `json:"extension"`
	Password  string `json:"password"`
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables.")
	}

	http.HandleFunc("/register", registerHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000" // Fallback port
	}

	log.Println("Starting server on :" + port + "...")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func verifySignature(payload, receivedSignature, secretKey string) bool {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(payload))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expectedSignature), []byte(receivedSignature))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("API-Key")
	signature := r.Header.Get("Signature")
	expectedApiKey := os.Getenv("API_KEY")
	secretKey := os.Getenv("SECRET_KEY")

	if apiKey != expectedApiKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !verifySignature(string(body), signature, secretKey) {
		http.Error(w, "Invalid Signature", http.StatusUnauthorized)
		return
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "Invalid Content-Type", http.StatusBadRequest)
		return
	}

	var users []UserData
	switch contentType {
	case "application/json":
		var singleUser UserData
		if err := json.Unmarshal(body, &singleUser); err != nil {
			http.Error(w, "Invalid JSON data", http.StatusBadRequest)
			return
		}
		users = []UserData{singleUser}
	case "text/csv":
		var err error
		users, err = parseCSV(body)
		if err != nil {
			http.Error(w, "Error parsing CSV", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	if err := processUserRegistration(users); err != nil {
		http.Error(
			w,
			fmt.Sprintf("Error processing registration: %v", err),
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User registration processed successfully!")
}

func parseCSV(data []byte) ([]UserData, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading headers: %v", err)
	}

	expectedHeaders := []string{"extension", "password", "name"}
	if !compareHeaders(headers, expectedHeaders) {
		return nil, fmt.Errorf("invalid CSV format. Expected headers: extension, password, name")
	}

	var users []UserData
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("error reading CSV row: %v", err)
		}

		users = append(users, UserData{
			Extension: record[0],
			Password:  record[1],
			Name:      record[2],
		})
	}

	return users, nil
}

func compareHeaders(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, header := range actual {
		if header != expected[i] {
			return false
		}
	}
	return true
}

func processUserRegistration(users []UserData) error {
	// Read the CSV template
	templateFile, err := os.Open("templates/extension_template.csv")
	if err != nil {
		return fmt.Errorf("error opening CSV template: %v", err)
	}
	defer templateFile.Close()

	templateReader := csv.NewReader(templateFile)
	headers, err := templateReader.Read()
	if err != nil {
		return fmt.Errorf("error reading template headers: %v", err)
	}

	// Create output file for bulkimport
	outputFile, err := os.CreateTemp("", "extension_*.csv")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer os.Remove(outputFile.Name())

	writer := csv.NewWriter(outputFile)

	// Write headers to the output file first
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing headers: %v", err)
	}

	for _, user := range users {
		row := make([]string, len(headers))
		for i, header := range headers {
			switch header {
			case "extension", "id", "user", "outboundcid", "emergency_cid", "cid_masquerade":
				row[i] = user.Extension
			case "secret":
				row[i] = user.Password
			case "name", "description":
				row[i] = user.Name
			case "dial":
				row[i] = fmt.Sprintf("PJSIP/%s", user.Extension)
			case "callerid":
				row[i] = fmt.Sprintf("%s <%s>", user.Name, user.Extension)
			case "defaultuser":
				row[i] = user.Extension
			case "devicedata":
				row[i] = user.Extension
			}
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing row: %v", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("error flushing writer: %v", err)
	}

	// Call fwconsole to import the extension
	importCmd := exec.Command(
		"fwconsole",
		"bulkimport",
		"--type=extensions",
		outputFile.Name(),
		"--replace",
	)
	importOutput, err := importCmd.CombinedOutput()
	log.Printf("Imported output is: %v\n Error is: %s", err, importOutput)
	if err != nil {
		return fmt.Errorf("error executing fwconsole import: %v\nOutput: %s", err, importOutput)
	}

	log.Printf("fwconsole import output: %s", importOutput)

	// Reload fwconsole
	reloadCmd := exec.Command("fwconsole", "reload")
	reloadOutput, err := reloadCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error executing fwconsole reload: %v\nOutput: %s", err, reloadOutput)
	}

	log.Printf("fwconsole reload output: %s", reloadOutput)

	return nil
}
