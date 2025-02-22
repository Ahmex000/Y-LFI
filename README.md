
# Y-LFI: Local File Inclusion Scanner

Y-LFI is a powerful and easy-to-use tool written in Go for detecting Local File Inclusion (LFI) vulnerabilities in web applications. It supports both GET and POST requests, allows custom headers and cookies, and can use a list of proxies for distributed scanning.

---

## Features

- **LFI Detection**: Scans for common LFI indicators like `/etc/passwd`.
- **GET & POST Support**: Works with both GET and POST requests.
- **Custom Headers**: Add custom headers to requests.
- **Custom Cookies**: Add custom cookies to requests.
- **Proxy Support**: Use a list of proxies for distributed scanning.
- **Rate Limiting**: Control the number of requests per second.
- **Output File**: Save results to a file for later analysis.

---

## Installation

1. **Install Go**:
   Make sure you have Go installed on your system. You can download it from [here](https://golang.org/dl/).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/username/Y-LFI.git
   cd Y-LFI
   ```

3. **Download Dependencies**:
   ```bash
   go mod download
   ```

4. **Build the Tool** (Optional):
   ```bash
   go build -o Y-LFI
   ```

---

## Usage

### Basic Usage
To scan a single URL with a payload file:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php
```

### Scan Multiple Endpoints
To scan multiple endpoints from a file:
```bash
go run Y-Lfi.go -p payloads.txt -f endpoints.txt
```

### Use Proxies
To use a list of proxies:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php -proxyfile proxies.txt
```

### Custom Headers
To add custom headers:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php -headers "Authorization: Bearer token,X-Custom-Header: value"
```

### Custom Cookies
To add custom cookies:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php -cookies "sessionid=12345; token=abcde"
```

### Save Results to a File
To save results to a file:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php -o results.txt
```

### Rate Limiting
To limit the number of requests per second:
```bash
go run Y-Lfi.go -p payloads.txt -u http://example.com/vulnerable.php -rate 2
```

---

## Command-Line Options

| Option        | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `-p`          | Path to the payload file (required).                                        |
| `-u`          | Single URL or request file for POST (required if `-f` is not used).         |
| `-f`          | File containing endpoints (required if `-u` is not used).                   |
| `-t`          | Number of concurrent threads (default: 10).                                 |
| `-m`          | HTTP method (GET or POST, default: GET).                                    |
| `-r`          | Send a normal request after this many requests (default: 10).               |
| `-proxy`      | Single proxy (e.g., `http://proxy.example.com:8080`).                       |
| `-proxyfile`  | File containing a list of proxies.                                          |
| `-o`          | Output file for results (e.g., `results.txt`).                              |
| `-rate`       | Max requests per second (default: 5).                                       |
| `-headers`    | Custom headers (e.g., `Header1:Value1,Header2:Value2`).                     |
| `-cookies`    | Custom cookies (e.g., `Cookie1=Value1; Cookie2=Value2`).                    |
| `-timeout`    | Request timeout in seconds (default: 10).                                   |
| `-skip-ssl-verify` | Skip SSL/TLS certificate verification.                                  |

---

## Example Payload File (`payloads.txt`)

```plaintext
../../../../etc/passwd
../../../../etc/hosts
../../../../etc/shadow
```

---

## Example Endpoints File (`endpoints.txt`)

```plaintext
http://example.com/vulnerable.php?file=test
http://example.com/another.php?page=index
```

---

## Example Proxies File (`proxies.txt`)

```plaintext
http://proxy1.example.com:8080
http://proxy2.example.com:8080
http://proxy3.example.com:8080
```

---

## Legal Disclaimer

Usage of Y-LFI for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

