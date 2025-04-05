package scanner

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// CreateDirIfNotExists creates a directory if it does not already exist.
func CreateDirIfNotExists(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}
	return nil
}

// WriteToFile writes data to a specified file, creating the file if it does not exist.
func WriteToFile(filePath string, data []byte) error {
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}

// LogError logs an error message to the console.
func LogError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

// ReadFileContents reads the contents of a file and returns it as a byte slice.
func ReadFileContents(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return data, nil
}

// GetAbsolutePath returns the absolute path of a given relative path.
func GetAbsolutePath(relativePath string) (string, error) {
	absPath, err := filepath.Abs(relativePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for %s: %w", relativePath, err)
	}
	return absPath, nil
}
