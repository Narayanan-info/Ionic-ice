# Ionic - ice Vulnerability Scanner

## Overview
The ionic-ice Vulnerability Scanner is a command-line tool designed to identify various web application vulnerabilities by scanning a list of subdomains. It supports multiple types of scans, including CORS, CRLF injection, and other common security misconfigurations. The tool is user-friendly and generates detailed reports for each scan.

## Features
- **CORS Vulnerability Scanning**: Detects Cross-Origin Resource Sharing misconfigurations.
- **CRLF Injection Scanning**: Identifies potential CRLF injection vulnerabilities.
- **Host Header Injection (HHI)**: Scans for Host Header Injection vulnerabilities.
- **X-Forwarded-For (XFF) Spoofing**: Checks for IP spoofing vulnerabilities.
- **Referer Header Manipulation**: Detects vulnerabilities related to Referer header manipulation.
- **Cache-Control & Pragma Bypass**: Identifies improper caching configurations.
- **Content-Type Mismatch (XSS)**: Scans for XSS vulnerabilities caused by Content-Type mismatches.
- **Strict-Transport-Security (HSTS) Bypass**: Checks for missing or misconfigured HSTS headers.
- **X-XSS-Protection Disabled**: Detects missing or disabled X-XSS-Protection headers.
- **Content Security Policy (CSP) Bypass**: Scans for weak or missing CSP configurations.
- **Server Header Leak**: Identifies information disclosure through server headers.
- **Cross-Origin-Opener-Policy (COOP) Bypass**: Checks for missing or misconfigured COOP headers.
- **Cross-Origin-Resource-Policy (CORP) Missing**: Scans for missing CORP headers.
- **X-Content-Type-Options Missing**: Detects missing or weak X-Content-Type-Options headers.
- **Feature-Policy (Permissions-Policy) Missing**: Identifies missing or misconfigured Feature-Policy headers.

## Installation
1. Ensure you have Go installed on your machine. You can download it from [golang.org](https://golang.org/dl/).
2. Clone the repository:
   ```sh
   git clone https://github.com/Narayanan-info/Ionic-ice.git
   ```
3. Navigate to the project directory:
   ```sh
   cd go-vulnerability-scanner
   ```
4. Install dependencies:
   ```sh
   go mod tidy
   ```

## Usage
1. Run the application:
   ```sh
   go run src/main.go
   ```
2. Upon starting, the tool will display an ASCII banner and present you with a list of scan options.
3. Select the desired scan type by entering the corresponding number.
4. Provide the path to a file containing the list of subdomains when prompted.
5. The tool will initiate the scan and save the results in the appropriate output directory.

## Scan Types
The following scan types are supported:
1. **CORS (Cross-Origin Resource Sharing)**
2. **CRLF (Carriage Return and Line Feed)**
3. **HHI (Host Header Injection)**
4. **XFF (X-Forwarded-For IP Spoofing)**
5. **Referer Header Manipulation**
6. **Cache-Control & Pragma Bypass**
7. **Content-Type Mismatch (XSS)**
8. **Strict-Transport-Security (HSTS) Bypass**
9. **X-XSS-Protection Disabled**
10. **Content Security Policy (CSP) Bypass**
11. **Server Header Leak (Info Disclosure)**
12. **Cross-Origin-Opener-Policy (COOP) Bypass**
13. **Cross-Origin-Resource-Policy (CORP) Missing**
14. **X-Content-Type-Options Missing**
15. **Feature-Policy (Permissions-Policy) Missing**

## Output
- Results for each scan are saved in dedicated output directories under the `output/` folder.
- Each scan type has its own subdirectory for storing results.

## Example
To scan for CORS vulnerabilities:
1. Run the tool:
   ```sh
   go run src/main.go
   ```
2. Select option `1` for CORS scanning.
3. Provide the path to the subdomain list file (e.g., `subdomains.txt`).
4. The results will be saved in the `output/cors` directory.

## Contributing
Contributions are welcome! If you have ideas for new features or improvements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.