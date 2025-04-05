# Go Vulnerability Scanner

## Overview
The Go Vulnerability Scanner is a tool designed to identify CORS vulnerabilities and CRLF injection vulnerabilities in web applications. It provides an easy-to-use interface for scanning a list of subdomains and generates reports on any vulnerabilities found.

## Features
- **CORS Vulnerability Scanning**: Checks for Cross-Origin Resource Sharing vulnerabilities and stores any findings in a dedicated output directory.
- **CRLF Injection Scanning**: Detects CRLF injection vulnerabilities and generates proof of concept (POC) files for any vulnerabilities found, stored in a separate output directory.
- **User-Friendly Interface**: Displays an ASCII banner upon initiation and provides a simple menu for selecting scan types.

## Installation
1. Ensure you have Go installed on your machine. You can download it from [golang.org](https://golang.org/dl/).
2. Clone the repository:
   ```
   git clone https://github.com/yourusername/go-vulnerability-scanner.git
   ```
3. Navigate to the project directory:
   ```
   cd go-vulnerability-scanner
   ```
4. Install dependencies:
   ```
   go mod tidy
   ```

## Usage
1. Run the application:
   ```
   go run src/main.go
   ```
2. Upon starting, the tool will display an ASCII banner and present you with options to scan for CORS or CRLF vulnerabilities.
3. Select the desired scan type by entering the corresponding number.
4. Input the path to your subdomain list when prompted.
5. The tool will initiate the scan and store results in the appropriate output directories:
   - CORS vulnerabilities will be stored in `src/output/cors`
   - CRLF injection POCs will be stored in `src/output/crlf`

## Output
- The results of the scans will be saved in their respective directories, allowing for easy access and review of any vulnerabilities found.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.