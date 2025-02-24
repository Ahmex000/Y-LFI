# Y-LFI

![image](https://github.com/user-attachments/assets/a13d887a-9331-4d80-bb13-19c11dd3eba7)


**Y-LFI** is a Local File Inclusion (LFI) vulnerability scanner written in Go. It is designed to test web applications for LFI vulnerabilities by injecting payloads into URL parameters and analyzing server responses for indicators of successful exploitation. The tool supports concurrent scanning, proxy usage, custom headers, and multiple detection methods.

**Created by Ahmex000**

## Features
- **Multi-threaded Scanning**: Supports concurrent requests with configurable threads (`-t`).
- **Flexible Input**: Accepts a single URL (`-u`) or a file containing multiple endpoints (`-f`).
- **Payload Injection**: Uses a customizable payload file (`-p`) to test various LFI vectors.
- **Detection Methods**: Supports multiple vulnerability detection reasons (`indicators`, `size`, `similarity`).
- **Rate Limiting**: Controls request rate with a configurable limit (`-rate`).
- **Proxy Support**: Works with single proxies (`-proxy`) or a proxy list (`-proxyfile`).
- **Custom Headers and Cookies**: Allows adding custom headers (`-headers`) and cookies (`-cookies`).
- **Output Logging**: Saves results to a file (`-o`).
- **Progress Tracking**: Displays real-time scanning progress (`-show-progress`).
- **Filtering Options**: Excludes specific response sizes (`-exclude-sizes`) or status codes (`-exclude-codes`).
- **Behavioral Control**: Options to hide non-vulnerable endpoints (`-hide-not-vulnerable`) or stop scanning a URL after a vulnerability is found (`-stop-on-vuln`).

## Stages of Operation
1. **Input Parsing**:
   - Reads payloads from the specified file (`-p`).
   - Accepts either a single URL (`-u`) or a list of endpoints from a file (`-f`).
   - Validates proxies if provided.

2. **Request Generation**:
   - Constructs URLs by combining endpoints with payloads.
   - Applies custom headers, cookies, and randomized realistic headers for stealth.

3. **Concurrent Scanning**:
   - Launches multiple worker threads (controlled by `-t`) to send HTTP requests.
   - Uses a rate limiter (controlled by `-rate`) to avoid overwhelming the target.

4. **Response Analysis**:
   - Checks for LFI indicators (e.g., `/etc/passwd`, `root:`) in the response body.
   - Analyzes response size differences (`size`) and similarity with baseline requests (`similarity`).
   - Logs successful detections and optionally stops per URL if `-stop-on-vuln` is enabled.

5. **Output**:
   - Prints vulnerable URLs to the console with details (e.g., reason, response size).
   - Saves results to an output file if specified (`-o`).
   - Displays a summary of successful payloads found.

## Installation
1. Ensure you have [Go](https://golang.org/doc/install) installed (version 1.16 or higher recommended).
2. Clone the repository:
   ```bash
   git clone https://github.com/ahmex000/Y-LFI.git
   cd Y-LFI
   ```
3. Install dependencies:
   ```bash
   go get github.com/gocolly/colly/v2
   go get golang.org/x/time/rate
   ```
4. Run the tool:
   ```bash
   go run Y-Lfi.go [options]
   ```

## Usage
```
go run Y-Lfi.go -p payloads.txt [-u url/request_file | -f endpoints.txt] [-t threads] [-m GET|POST] [-r interval] [-proxy proxy | -proxyfile proxies_file] [-o output_file] [-rate requests_per_sec] [-headers 'Header1:Value1,Header2:Value2'] [-cookies 'Cookie1=Value1;Cookie2=Value2'] [-timeout seconds] [-skip-ssl-verify] [-reasons 'indicators,size,similarity'] [-show-progress] [-vuln-only] [-exclude-sizes sizes] [-exclude-codes codes] [-hide-not-vulnerable] [-stop-on-vuln]
```

### Important Notes
- **Single URL vs. File**: The tool performs more consistently with a single URL (`-u`) compared to a file of endpoints (`-f`). Using `-u` ensures all payloads are tested against a single target without potential issues in file parsing or channel management.
- **Legal Disclaimer**: Usage of Y-LFI against targets without prior consent is illegal. Use responsibly and only on systems you have permission to test.

### Preferred Command
For optimal performance and reliability, especially when testing a single endpoint, use:
```bash
go run Y-Lfi.go -u http://example.com/?file= -p payloads.txt -hide-not-vulnerable -stop-on-vuln -rate 100 -t 20 -reasons indicators,size,similarity
```
This command focuses on a single URL, stops scanning a URL after detecting a vulnerability, and uses a high request rate with multiple threads for efficiency.

### Using a File as a Single URL
If you have a file (e.g., `urls.txt`) with one URL per line and want to treat it as a single input, you can use `cat` with `-u`:
```bash
go run Y-Lfi.go -u "$(cat urls.txt)" -p payloads.txt -hide-not-vulnerable -stop-on-vuln -rate 100 -t 20 -reasons indicators,size,similarity
```
**Note**: This works best if `urls.txt` contains a single URL. If it has multiple URLs, only the last one will be used due to how shell substitution works. For multiple URLs, stick to `-f`.

### Example with File Input
For scanning multiple endpoints from a file:
```bash
go run Y-Lfi.go -f urls.txt -p payloads.txt -hide-not-vulnerable -stop-on-vuln -rate 100 -t 20 -reasons indicators,size,similarity
```
**Preferred Command for File Input** (if you must use a file):
```bash
go run Y-Lfi.go -f urls.txt -p payloads.txt -hide-not-vulnerable -stop-on-vuln -rate 100 -t 20 -reasons indicators,size,similarity
```
However, expect potentially less consistent results compared to `-u` due to threading and file handling overhead.

## Example Files
### `payloads.txt`
```
/etc/passwd
/etc/shadow
../../etc/passwd
/etc/apache2/apache2.conf
```

### `urls.txt`
```
http://173.212.240.12:5000/?file=
http://example.com/?page=
```

## Troubleshooting
- **Inconsistent Results**: Use `-u` for a single URL to avoid issues with file parsing or channel management.
- **No Requests Sent**: Check if `payloads.txt` and `urls.txt` are non-empty and correctly formatted.
- **Rate Limiting**: Increase `-rate` if the target can handle more requests, or decrease it if you're hitting server limits.

## Contributing
Feel free to submit pull requests or open issues for bug reports and feature suggestions!

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

**Disclaimer**: The developers are not responsible for any misuse or damage caused by this tool.
```
