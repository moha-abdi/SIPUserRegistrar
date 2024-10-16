package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	var userData UserData
	if err := json.Unmarshal(body, &userData); err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	if err := processUserRegistration(userData); err != nil {
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

func processUserRegistration(userData UserData) error {
	// Read the CSV template
	templateFile, err := os.Open("templates/extension_template.csv")
	if err != nil {
		return fmt.Errorf("error opening CSV template: %v", err)
	}
	defer templateFile.Close()

	reader := csv.NewReader(templateFile)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("error reading CSV template: %v", err)
	}

	if len(records) < 2 {
		return fmt.Errorf("CSV template does not have enough rows")
	}

	// Update the CSV data with user information
	for j := range records[0] {
		switch records[0][j] { // Use header row to identify the column
		case "extension", "id", "user", "outboundcid", "emergency_cid", "cid_masquerade":
			records[1][j] = userData.Extension
		case "secret":
			records[1][j] = userData.Password
		case "name", "description":
			records[1][j] = userData.Name
		case "dial":
			records[1][j] = fmt.Sprintf("PJSIP/%s", userData.Extension)
		case "callerid":
			records[1][j] = fmt.Sprintf("%s <%s>", userData.Name, userData.Extension)
		case "defaultuser":
			records[1][j] = userData.Extension
		case "devicedata":
			records[1][j] = userData.Extension
		}
	}

	// Write the updated CSV data to a temporary file
	tempFile, err := os.CreateTemp("", "extension_*.csv")
	log.Println("The created temp file is: ", tempFile.Name())
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	writer := csv.NewWriter(tempFile)
	if err := writer.WriteAll(records); err != nil {
		return fmt.Errorf("error writing CSV data: %v", err)
	}
	writer.Flush()

	// Call fwconsole to import the extension
	importCmd := exec.Command(
		"fwconsole",
		"bulkimport",
		"--type=extensions",
		tempFile.Name(),
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
