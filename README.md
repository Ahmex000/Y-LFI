# Y-Lfi

A powerful Local File Inclusion (LFI) vulnerability scanner written in Go. This tool is designed to test web applications for LFI vulnerabilities by injecting payloads into URL parameters, POST requests, and cookies. It supports multiple features like proxy rotation, IP spoofing, and WAF evasion techniques.

## Features
- **Multi-Method Support**: Scans with both GET and POST requests.
- **Parameter Testing**: Automatically detects and tests multiple URL parameters.
- **Cookie Testing**: Tests LFI payloads in cookies for POST requests.
- **IP Spoofing**: Randomizes `X-Forwarded-For`, `Forwarded`, and `X-Real-IP` headers with fake IPs.
- **Proxy Support**: Use a single proxy or a list of proxies for request rotation.
- **User-Agent Rotation**: Includes a diverse list of User-Agents to mimic real traffic.
- **WAF Evasion**: Sends normal requests at configurable intervals to avoid detection.
- **Concurrency**: Multi-threaded scanning with adjustable thread count.
- **Colorized Output**: Green for successful LFI detections, red for errors.

## Prerequisites
- **Go**: Ensure you have Go installed (version 1.16 or higher recommended). [Download Go](https://golang.org/dl/).
- **Payloads File**: A text file with LFI payloads (e.g., `payloads.txt`).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Ahmex000/Y-LFI.git
   cd Y-LFI
   ```

## Usage
Run the tool with the following command structure:
```bash
go run Y-LFI.go -p <payloads_file> [-u <url/request_file> | -f <endpoints_file>] [-t threads] [-m GET|POST] [-r interval] [-proxy proxy | -proxyfile proxies_file]
```

### Options
| Flag           | Description                                      | Default       | Example                              |
|----------------|--------------------------------------------------|---------------|--------------------------------------|
| `-p`           | Path to the payloads file (required)            | -             | `-p payloads.txt`                   |
| `-u`           | Single URL (GET) or request file (POST)         | -             | `-u "https://example.com/?file="`   |
| `-f`           | File containing endpoints (GET only)            | -             | `-f endpoints.txt`                  |
| `-t`           | Number of concurrent threads                    | 10            | `-t 20`                             |
| `-m`           | HTTP method (GET or POST)                       | GET           | `-m POST`                           |
| `-r`           | Send normal request after this many requests    | 10            | `-r 5`                              |
| `-proxy`       | Single proxy URL                                | -             | `-proxy "http://proxy.com:8080"`    |
| `-proxyfile`   | File containing proxy list                      | -             | `-proxyfile proxies.txt`            |

### Examples
1. **Scan a single URL with GET:**
   ```bash
   go run Y-LFI.go -p payloads.txt -u "https://example.com/image?filename=¶m2=" -t 10 -m GET -r 5
   ```
2. **Scan multiple endpoints from a file:**
   ```bash
   go run Y-LFI.go -p payloads.txt -f endpoints.txt -t 20 -m GET -r 10 -proxy "http://proxy.example.com:8080"
   ```
3. **Scan with POST requests from a request file:**
   - Example `request.txt`:
     ```
     https://example.com/api {"key":"value"}
     https://example.com/api name=test&age=25
     ```
   - Command:
     ```bash
     go run Y-LFI.go -p payloads.txt -u request.txt -t 10 -m POST -r 5 -proxyfile proxies.txt
     ```

### File Formats
- **Payloads File (`payloads.txt`)**: One LFI payload per line.
  ```
  ../../../../etc/passwd
  ../../../../proc/self/environ
  ../../../../windows/win.ini
  ```
- **Endpoints File (`endpoints.txt`, for GET)**: One URL per line.
  ```
  https://example.com/?file=
  https://test.com/index.php?page=
  ```
- **Request File (`request.txt`, for POST)**: Full request (URL + body) per line, separated by a space.
  ```
  https://example.com/api {"key":"value"}
  https://example.com/api key=value
  ```
- **Proxy File (`proxies.txt`)**: One proxy URL per line.
  ```
  http://proxy1.example.com:8080
  http://proxy2.example.com:3128
  ```

## Output
- **Success**: Green text for detected LFI vulnerabilities.
  ```
  [+] Potential LFI found: https://example.com/?file=../../../../etc/passwd
      Indicator: root
  ```
- **Errors**: Red text for failed requests or issues.
  ```
  [-] Error on https://example.com/?file=../../../../etc/passwd (attempt 1): dial tcp: connection refused
  ```

## Notes
- **Proxy Usage**: Ensure proxies are valid and functional. Invalid proxies will result in connection errors.
- **WAF Evasion**: Adjust `-r` to send normal requests more or less frequently based on the target's WAF sensitivity.
- **Legal Warning**: Use this tool only on systems you have explicit permission to test. Unauthorized scanning is illegal.

## Contributing
Feel free to submit issues or pull requests if you have suggestions or improvements!


## Credits
Developed by [Ahmex000]. Powered by xAI's Grok.

