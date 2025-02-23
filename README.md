# Y-LFI

![image](https://github.com/user-attachments/assets/1e821ef9-7d93-47bb-ac2c-5dd1d9ac31d4)

  
*Y-LFI - A powerful Local File Inclusion (LFI) vulnerability scanner written in Go.*

---

## Overview

Y-LFI is an advanced tool designed to detect Local File Inclusion (LFI) vulnerabilities in web applications. Built with Go by **Ahmex000**, it offers multi-threaded scanning, proxy support, customizable payloads, and flexible detection mechanisms. Whether you're a security researcher or a penetration tester, Y-LFI provides a robust solution for identifying LFI flaws efficiently.

---

## Features

- **Multi-Threaded Scanning**: Speed up your scans with configurable concurrent threads.
- **Flexible Payloads**: Use custom payload files for GET or POST requests.
- **Proxy Support**: Scan through a single proxy or a list of proxies with validation.
- **Custom Headers & Cookies**: Add your own headers and cookies for advanced testing.
- **Detection Customization**: Choose detection methods (`indicators`, `size`, `similarity`) with a default of `indicators`.
- **Rate Limiting**: Control request rates to avoid detection or server overload.
- **Progress Tracking**: Real-time progress display with successful payload count.
- **Output Logging**: Save results to a file for later analysis.
- **SSL/TLS Flexibility**: Option to skip certificate verification for testing.

---

## Installation

### Prerequisites
- [Go](https://golang.org/dl/) (version 1.16 or higher)
- Git

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Ahmex000/Y-LFI.git
   cd Y-LFI
   ```
2. Install dependencies:
   ```bash
   go mod init Y-LFI
   go get golang.org/x/time/rate
   ```
3. Build the tool:
   ```bash
   go build YLfi.go
   ```
4. Run it:
   ```bash
   ./YLfi -h
   ```

---

## Usage

Y-LFI supports a variety of command-line flags to customize your scans. Here's the basic syntax:

```bash
go run YLfi.go -p <payloads_file> [-u <url> | -f <endpoints_file>] [options]
```

### Required Flags
- `-p <file>`: Path to the payload file (e.g., `payloads.txt`).
- `-u <url>`: Single URL to scan (for GET) or request file (for POST).
- `-f <file>`: File containing multiple endpoints to scan.

### Optional Flags
| Flag                   | Description                                      | Default            |
|-----------------------|--------------------------------------------------|--------------------|
| `-t <int>`            | Number of concurrent threads                    | 10                |
| `-m <GET|POST>`       | HTTP method                                     | GET               |
| `-r <int>`            | Send a normal request after this many requests  | 10                |
| `-proxy <url>`        | Single proxy URL (e.g., `http://proxy:8080`)    | None              |
| `-proxyfile <file>`   | File with proxy list                            | None              |
| `-o <file>`           | Output file for results                         | None              |
| `-rate <int>`         | Max requests per second                         | 5                 |
| `-headers <string>`   | Custom headers (e.g., `Header1:Value1,Header2:Value2`) | None       |
| `-cookies <string>`   | Custom cookies (e.g., `Cookie1=Value1;Cookie2=Value2`) | None       |
| `-timeout <int>`      | Request timeout in seconds                      | 10                |
| `-skip-ssl-verify`    | Skip SSL/TLS certificate verification           | False             |
| `-reasons <string>`   | Detection methods (e.g., `indicators,size`)     | `indicators`      |
| `-show-progress`      | Show scanning progress                          | True              |
| `-vuln-only`          | Show only vulnerable URLs                       | False             |
| `-exclude-sizes <list>` | Comma-separated sizes to exclude (e.g., `50,100`) | None           |
| `-exclude-codes <list>` | Comma-separated status codes to exclude (e.g., `404,500`) | None   |
| `-hide-not-vulnerable`| Hide non-vulnerable endpoints                   | False             |

### Examples
1. **Scan a single URL with default settings:**
   ```bash
   go run YLfi.go -p payloads.txt -u "http://example.com?page="
   ```
2. **Scan multiple endpoints with custom threads and output:**
   ```bash
   go run YLfi.go -p payloads.txt -f endpoints.txt -t 20 -o results.txt
   ```
3. **POST request with proxies and custom headers:**
   ```bash
   go run YLfi.go -p payloads.txt -u request.txt -m POST -proxyfile proxies.txt -headers "X-Test:Value" -reasons "indicators,size"
   ```
4. **Silent mode with only vulnerable results:**
   ```bash
   go run YLfi.go -p payloads.txt -u "http://example.com" -vuln-only -hide-not-vulnerable
   ```

---

## Detection Methods
Y-LFI uses three methods to identify LFI vulnerabilities:
- **Indicators**: Checks for sensitive file patterns (e.g., `/etc/passwd`, `win.ini`) in responses. *(Default)*
- **Size**: Compares response size differences with and without payloads.
- **Similarity**: Analyzes response similarity to detect anomalies.

Use the `-reasons` flag to specify which methods to use (e.g., `-reasons "indicators,size"`).

---

## Payload File Format
- For GET: One payload per line (e.g., `../../etc/passwd`).
- For POST: Full request body per line (e.g., `http://example.com data=../../etc/passwd`).

---

## Legal Disclaimer
**Y-LFI is intended for authorized security testing only.** Usage against targets without prior consent is illegal. The developer (Ahmex000) assumes no liability for misuse or damage caused by this tool. Always comply with local, state, and federal laws.

---

## Contributing
Contributions are welcome! Feel free to:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a Pull Request.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contact
- **Author**: Ahmex000
- **GitHub**: [github.com/Ahmex000](https://github.com/Ahmex000)
- **Issues**: [Report a bug or request a feature](https://github.com/Ahmex000/Y-LFI/issues)

---

*Happy Hacking Responsibly!*
