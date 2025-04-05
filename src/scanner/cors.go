package scanner

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ANSI color codes
const (
	ColorResetCORS  = "\033[0m"
	ColorRedCORS    = "\033[31m"
	ColorGreenCORS  = "\033[32m"
	ColorYellowCORS = "\033[33m"
	// Removed duplicate declaration of ColorBlue
	ColorCyanCORS = "\033[36m"
	// Removed duplicate declaration of ColorWhite
)

// ScanCORS checks for CORS vulnerabilities in the provided subdomains.
func ScanCORS(subdomains []string) {
	// Display the name tag for the scan type with colors
	fmt.Println(ColorCyanCORS + "===================================" + ColorResetCORS)
	fmt.Println(ColorGreenCORS + "           CORS Scan Tool          " + ColorResetCORS)
	fmt.Println(ColorCyanCORS + "===================================" + ColorResetCORS)

	outputDir := "./output/cors"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		fmt.Println(ColorRedCORS+"Error creating output directory:"+ColorResetCORS, err)
		return
	}

	// Define payloads for different CORS scenarios
	payloads := []string{
		"http://evil.com",     // Malicious domain
		"https://example.com", // Trusted domain
		"*",                   // Wildcard
		"null",                // Null origin
	}

	// Open a file to save the results
	resultsFile := fmt.Sprintf("%s/cors_vulnerabilities.txt", outputDir)
	results, err := os.OpenFile(resultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(ColorRedCORS+"Error creating results file:"+ColorResetCORS, err)
		return
	}
	defer results.Close()

	// Write the banner to the file
	banner := "===================================\n           CORS Scan Tool          \n===================================\n\n"
	_, err = results.WriteString(banner)
	if err != nil {
		fmt.Printf(ColorRedCORS+"Error writing banner to results file: %v\n"+ColorResetCORS, err)
		return
	}

	// Iterate over each subdomain
	for _, subdomain := range subdomains {
		// Ensure the URL has a valid scheme
		var url string
		if strings.HasPrefix(subdomain, "http://") || strings.HasPrefix(subdomain, "https://") {
			url = subdomain
		} else {
			url = fmt.Sprintf("http://%s", subdomain)
		}

		fmt.Printf(ColorYellowCORS+"Scanning %s for CORS vulnerabilities...\n"+ColorResetCORS, url)

		for _, payload := range payloads {
			// Create a custom HTTP request
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Printf(ColorRedCORS+"Error creating request for %s: %v\n"+ColorResetCORS, url, err)
				continue
			}

			// Add the Origin header with the payload
			req.Header.Set("Origin", payload)

			// Perform the HTTP request
			client := &http.Client{
				Timeout: 10 * time.Second, // Timeout for each request
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					req.Header.Set("Origin", payload) // Preserve the Origin header during redirects
					return nil
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf(ColorRedCORS+"Error accessing %s with payload %s: %v\n"+ColorResetCORS, url, payload, err)
				continue
			}
			defer resp.Body.Close()

			// Check for CORS headers
			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
			allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

			// Analyze the response for vulnerabilities
			if allowOrigin == payload || allowOrigin == "*" {
				vulnerableData := fmt.Sprintf(
					"Vulnerable CORS found at %s:\n  Origin: %s\n  Access-Control-Allow-Origin: %s\n  Access-Control-Allow-Methods: %s\n  Access-Control-Allow-Credentials: %s\n\n",
					url, payload, allowOrigin, allowMethods, allowCredentials,
				)

				// Write the vulnerable data to the results file
				_, err := results.WriteString(vulnerableData)
				if err != nil {
					fmt.Printf(ColorRedCORS+"Error writing to results file: %v\n"+ColorResetCORS, err)
				} else {
					fmt.Printf(ColorGreenCORS+"Vulnerability logged for %s payload %s\n"+ColorResetCORS, url, payload)
				}
			}
		}

		// Add a separator after each domain's findings
		separator := "=========================\n"
		_, err = results.WriteString(separator)
		if err != nil {
			fmt.Printf(ColorRedCORS+"Error writing separator to results file: %v\n"+ColorResetCORS, err)
		}
	}
	fmt.Println(ColorGreenCORS+"CORS scan completed. Results saved to:"+ColorResetCORS, resultsFile)
}
