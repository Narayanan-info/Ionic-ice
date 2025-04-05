package scanner

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ScanReferer checks for Referer Header Manipulation vulnerabilities in the provided subdomains.
func ScanReferer(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   Referer Header Manipulation    "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/referer"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define payloads for Referer Header Manipulation testing
	payloads := []string{
		"https://evil.com",         // Malicious domain
		"https://phishing.com",     // Phishing domain
		"https://localhost",        // Localhost
		"https://127.0.0.1",        // Localhost IP
		"https://example.com",      // Trusted domain
		"https://google.com",       // Common domain
		"",                         // Empty Referer header
		" ",                        // Space as Referer header
		"https://evil.com/path",    // Malicious domain with path
		"https://evil.com?param=1", // Malicious domain with query
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "referer_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   Referer Header Manipulation    \n===================================\n\n"
	_, err = results.WriteString(bannerText)
	if err != nil {
		fmt.Printf(errorMsg("Error writing banner to results file: %v\n"), err)
		return
	}

	// Iterate over each subdomain
	for _, subdomain := range subdomains {
		// Ensure the URL has a valid scheme
		var baseURL string
		if strings.HasPrefix(subdomain, "http://") || strings.HasPrefix(subdomain, "https://") {
			baseURL = subdomain
		} else {
			baseURL = fmt.Sprintf("http://%s", subdomain)
		}

		fmt.Printf(color.YellowString("Scanning %s for Referer Header Manipulation vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("GET", baseURL, nil)
			if err != nil {
				fmt.Printf(errorMsg("Error creating request for %s: %v\n"), baseURL, err)
				continue
			}

			// Add the Referer header with the payload
			req.Header.Set("Referer", payload)

			// Perform the HTTP request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with Referer %s: %v\n"), baseURL, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Check for signs of Referer header manipulation in the response
			if resp.StatusCode == http.StatusOK && strings.Contains(resp.Request.Header.Get("Referer"), payload) {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  Referer: %s\n  Status Code: %d\n",
					baseURL, payload, resp.StatusCode,
				))
			}
		}

		// Write findings for the subdomain to the file
		if len(findings) > 0 {
			_, err := results.WriteString(fmt.Sprintf("Findings for %s:\n%s\n=========================\n", baseURL, strings.Join(findings, "\n")))
			if err != nil {
				fmt.Printf(errorMsg("Error writing findings to results file: %v\n"), err)
			}
		}
	}

	fmt.Println(success("Referer Header Manipulation scan completed. Results saved to:"), resultsFile)
}
