package scanner

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ScanContentType checks for Content-Type Mismatch (XSS) vulnerabilities in the provided subdomains.
func ScanContentType(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   Content-Type Mismatch (XSS)    "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/content_type"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define payloads for Content-Type Mismatch testing
	payloads := []string{
		"text/html",                         // Force HTML rendering
		"application/json",                  // Force JSON rendering
		"text/plain",                        // Force plain text rendering
		"application/javascript",            // Force JavaScript rendering
		"image/svg+xml",                     // Force SVG rendering
		"application/xml",                   // Force XML rendering
		"multipart/form-data",               // Force multipart form rendering
		"application/x-www-form-urlencoded", // Force URL-encoded form rendering
	}

	// Define XSS payload to inject
	xssPayload := `<script>alert(1)</script>`

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "content_type_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   Content-Type Mismatch (XSS)    \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for Content-Type Mismatch vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("POST", baseURL, strings.NewReader(xssPayload))
			if err != nil {
				fmt.Printf(errorMsg("Error creating request for %s: %v\n"), baseURL, err)
				continue
			}

			// Add the Content-Type header with the payload
			req.Header.Set("Content-Type", payload)

			// Perform the HTTP request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with Content-Type %s: %v\n"), baseURL, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Read the response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf(errorMsg("Error reading response body from %s: %v\n"), baseURL, err)
				continue
			}

			// Check for signs of Content-Type mismatch or XSS payload execution
			contentType := resp.Header.Get("Content-Type")
			if contentType != payload && strings.Contains(string(body), xssPayload) {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  Sent Content-Type: %s\n  Received Content-Type: %s\n  XSS Payload Executed: %s\n",
					baseURL, payload, contentType, xssPayload,
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

	fmt.Println(success("Content-Type Mismatch scan completed. Results saved to:"), resultsFile)
}
