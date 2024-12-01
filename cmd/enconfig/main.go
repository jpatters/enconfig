package main

import (
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/jpatters/enconfig"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "enconfig",
	Short: "Encrypted configuration management tool",
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new encrypted configuration",
	Run:   createConfig,
}

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit encrypted configuration in your default editor",
	Run:   editConfig,
}

var environment string

func init() {
	createCmd.Flags().StringVarP(&environment, "environment", "e", "", "Environment name (required)")
	createCmd.MarkFlagRequired("environment")
	rootCmd.AddCommand(createCmd)

	editCmd.Flags().StringVarP(&environment, "environment", "e", "", "Environment name (required)")
	editCmd.MarkFlagRequired("environment")
	rootCmd.AddCommand(editCmd)
}

func createConfig(cmd *cobra.Command, args []string) {
	key, err := enconfig.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	if err := enconfig.SaveKey(key, environment); err != nil {
		log.Fatalf("Error saving key: %v", err)
	}

	if err := enconfig.CreateEmptyCredentials(environment, key); err != nil {
		log.Fatalf("Error creating credentials: %v", err)
	}
}

func getConfigPath() (string, error) {
	return os.Getwd()
}

func editConfig(cmd *cobra.Command, args []string) {
	path, err := getConfigPath()
	if err != nil {
		log.Fatalf("Error getting config path: %v", err)
		return
	}
	f := os.DirFS(path)
	key, err := enconfig.LoadKey(f, environment)
	if err != nil {
		log.Fatalf("Error loading key: %v", err)
	}

	// Read and decrypt the existing credentials
	decrypted, err := enconfig.ReadAndDecryptCredentials(f, environment, key)
	if err != nil {
		log.Fatalf("Error decrypting credentials: %v", err)
	}

	// Create temporary file
	tmpfile, err := os.CreateTemp("", "credentials-*.yaml")
	if err != nil {
		log.Fatalf("Error creating temporary file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write decrypted content to temporary file
	if _, err := tmpfile.Write(decrypted); err != nil {
		log.Fatalf("Error writing to temporary file: %v", err)
	}
	tmpfile.Close()

	// Get editor from environment or fallback to vi
	editor := os.Getenv("EDITOR")
	var editorArgs []string
	if editor == "" {
		editor = "vi"
		editorArgs = []string{tmpfile.Name()}
	} else {
		editorParts := strings.Fields(editor)
		editor = editorParts[0]
		editorArgs = append(editorParts[1:], tmpfile.Name())
	}

	// Open editor
	c := exec.Command(editor, editorArgs...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		log.Fatalf("Error running editor: %v", err)
	}

	// Read modified content
	modified, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		log.Fatalf("Error reading modified file: %v", err)
	}

	// Encrypt and save the modified content
	if err := enconfig.EncryptAndSaveCredentials(f, environment, modified, key); err != nil {
		log.Fatalf("Error saving encrypted credentials: %v", err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
