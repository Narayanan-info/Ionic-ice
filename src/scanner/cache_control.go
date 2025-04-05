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

// ScanCacheControl checks for Cache-Control & Pragma Bypass vulnerabilities in the provided subdomains.
func ScanCacheControl(subdomains []string) {
	// Display the name tag for the scan type with colors
	banner := color.New(color.FgCyan).SprintFunc()
	success := color.New(color.FgGreen).SprintFunc()
	errorMsg := color.New(color.FgRed).SprintFunc()

	fmt.Println(banner("==================================="))
	fmt.Println(success("   Cache-Control & Pragma Bypass   "))
	fmt.Println(banner("==================================="))

	outputDir := "./output/cache_control"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(errorMsg("Error creating output directory:"), err)
		return
	}

	// Define payloads for Cache-Control & Pragma testing
	payloads := []string{
		"no-store",                // Prevent caching
		"no-cache",                // Force revalidation
		"max-age=0",               // Expire immediately
		"must-revalidate",         // Force revalidation
		"public",                  // Allow caching by any cache
		"private",                 // Allow caching only by the client
		"proxy-revalidate",        // Force revalidation by proxies
		"immutable",               // Indicate the response will not change
		"no-transform",            // Prevent transformations
		"Pragma: no-cache",        // Legacy HTTP/1.0 header
		"Cache-Control: no-cache", // Explicit Cache-Control header
	}

	// Open a file to save the results
	resultsFile := filepath.Join(outputDir, "cache_control_vulnerabilities.txt")
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(errorMsg("Error creating results file:"), err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	bannerText := "===================================\n   Cache-Control & Pragma Bypass   \n===================================\n\n"
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

		fmt.Printf(color.YellowString("Scanning %s for Cache-Control & Pragma Bypass vulnerabilities...\n"), baseURL)

		// Collect findings for the subdomain
		var findings []string

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("GET", baseURL, nil)
			if err != nil {
				fmt.Printf(errorMsg("Error creating request for %s: %v\n"), baseURL, err)
				continue
			}

			// Add the Cache-Control or Pragma header with the payload
			if strings.HasPrefix(payload, "Pragma") {
				req.Header.Set("Pragma", strings.TrimPrefix(payload, "Pragma: "))
			} else if strings.HasPrefix(payload, "Cache-Control") {
				req.Header.Set("Cache-Control", strings.TrimPrefix(payload, "Cache-Control: "))
			} else {
				req.Header.Set("Cache-Control", payload)
			}

			// Perform the HTTP request
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(errorMsg("Error accessing %s with Cache-Control/Pragma %s: %v\n"), baseURL, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Check for signs of improper caching in the response
			cacheControl := resp.Header.Get("Cache-Control")
			pragma := resp.Header.Get("Pragma")
			if cacheControl == "" && pragma == "" {
				findings = append(findings, fmt.Sprintf(
					"Vulnerable URL: %s\n  Payload: %s\n  Response lacks Cache-Control/Pragma headers.\n",
					baseURL, payload,
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

	fmt.Println(success("Cache-Control & Pragma Bypass scan completed. Results saved to:"), resultsFile)
}
