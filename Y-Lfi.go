package main

import (
        "bufio"
        "bytes"
        "context"
        "crypto/tls"
        "flag"
        "fmt"
        "math/rand"
        "net/http"
        "net/url"
        "os"
        "regexp"
        "strconv"
        "strings"
        "sync"
        "time"

        "github.com/gocolly/colly/v2"
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
const (
        maxRetries      = 3
        rateLimitPerSec = 5 // Max requests per second
)

var (
        proxies            []string
        proxyIndex         int
        proxyMutex         sync.Mutex
        resultFile         *os.File
        resultMutex        sync.Mutex
        limiter            = rate.NewLimiter(rate.Limit(rateLimitPerSec), 1)
        showProgress       bool
        vulnOnly           bool
        excludeSizes       []int
        excludeCodes       []int
        hideNotVulnerable  bool
        successfulPayloads int
        successfulMutex    sync.Mutex
        stopOnVuln         bool // New flag
)

var acceptOptions = []string{
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.7",
        "application/json, text/javascript, */*; q=0.01",
        "*/*",
}

var acceptLanguageOptions = []string{
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "fr-FR,fr;q=0.9",
        "de-DE,de;q=0.8",
        "es-ES,es;q=0.7",
        "zh-CN,zh;q=0.9",
        "ja-JP,ja;q=0.8",
}

var acceptEncodingOptions = []string{
        "gzip, deflate, br",
        "gzip, deflate",
        "br",
        "", // أحيانًا مفيش Accept-Encoding
}

var connectionOptions = []string{
        "keep-alive",
        "close",
}

var cacheControlOptions = []string{
        "no-cache",
        "no-store",
        "max-age=0",
        "", // أحيانًا مفيش Cache-Control
}

var refererOptions = []string{
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.facebook.com/",
        "", // أحيانًا مفيش Referer
}

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

var indicators = []string{
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/resolv.conf",
        "/etc/fstab", "/etc/motd", "/etc/issue", "/etc/sudoers", "/etc/crontab",
        "/etc/sysctl.conf", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
        "/root/", "bashrc", "GOROOT", "/root/.bashrc", "/root/.ssh/",
        "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa", "/root/.ssh/known_hosts",
        "/home/admin/", "/home/www-data/", "root:", "admin:", "nobody:", "daemon:",
        "bin:", "sys:", "sync:", "games:", "www-data:", "/bin/", "/bin/bash",
        "/bin/sh", "/sbin/", "/sbin/init", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
        "/usr/local/sbin/", "/var/", "/var/log/", "/var/www/", "/var/www/html/", "/proc/",
        "/proc/self/environ", "/proc/self/stat", "/proc/self/status", "/proc/self/cmdline",
        "/proc/cpuinfo", "/proc/meminfo", "/proc/version", "/proc/mounts", "/var/log/auth.log",
        "/var/log/syslog", "/var/log/messages", "/var/log/apache2/access.log",
        "/var/log/apache2/error.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/etc/apache2/apache2.conf", "/etc/apache2/httpd.conf", "/etc/apache2/sites-enabled/",
        "/etc/nginx/nginx.conf", "/etc/php.ini", "/etc/php/php.ini", "/etc/httpd/conf/httpd.conf",
        "/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/postgresql/pg_hba.conf",
        "/etc/postgresql/postgresql.conf", "mysql:", "postgres:", "dbuser:", "dbname=",
        "password=", "DB_PASSWORD=", "DB_USERNAME=", "DB_HOST=", "mysql_connect(",
        "mysqli_connect(", "pg_connect(", "/var/www/config/", "/var/www/conf/", "/var/www/.env",
        "/app/config/", "/config/", "/conf/", "/internal/", "/private/", "/secret/", "/keys/",
        "/credentials/", "/data/", "/db/", "/database/", ":/bin/bash", ":/bin/sh",
        ":/sbin/nologin", ":/usr/bin/", "$6$", "$1$", "$5$", "127.0.0.1", "nameserver",
        "PATH=", "USER=", "C:\\Windows\\", "C:\\Windows\\System32\\", "C:\\WINNT\\",
        "C:\\WINNT\\system32\\", "C:\\Program Files\\", "C:\\Users\\",
        "win.ini(.[a-zA-Z0-9]+)?|win.ini[-_?=/\\.]?", "system.ini", "boot.ini", "ntldr",
        "\\System32\\", "\\Windows\\", "Administrator:", "SYSTEM:", "uid=", "gid=", " pid=",
        "kernel", "Linux version", "VirtualHost ", "/etc/apache",
}

func main() {
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
        reasonsFlag := flag.String("reasons", "indicators", "Reasons to determine vulnerability (e.g., 'indicators,size,similarity')")
        flag.BoolVar(&showProgress, "show-progress", true, "Show progress during scanning")
        flag.BoolVar(&vulnOnly, "vuln-only", false, "Show only vulnerable URLs")
        excludeSizesFlag := flag.String("exclude-sizes", "", "Comma-separated list of response sizes to exclude")
        excludeCodesFlag := flag.String("exclude-codes", "", "Comma-separated list of status codes to exclude")
        flag.BoolVar(&hideNotVulnerable, "hide-not-vulnerable", false, "Hide not vulnerable endpoints")
        flag.BoolVar(&stopOnVuln, "stop-on-vuln", false, "Stop sending payloads to a URL after detecting a vulnerability") // New flag
        flag.Parse()

        limiter.SetLimit(rate.Limit(*rateLimit))

        if *payloadFile == "" || (*urlFlag == "" && *endpointFile == "") {
                fmt.Println("Usage: go run YLfi.go -p payloads.txt [-u url/request_file | -f endpoints.txt] [-t threads] [-m GET|POST] [-r interval] [-proxy proxy | -proxyfile proxies_file] [-o output_file] [-rate requests_per_sec] [-headers 'Header1:Value1,Header2:Value2'] [-cookies 'Cookie1=Value1; Cookie2=Value2'] [-timeout 10] [-skip-ssl-verify] [-reasons 'indicators,size,similarity'] [-show-progress] [-vuln-only] [-exclude-sizes 50,100] [-exclude-codes 404,500] [-hide-not-vulnerable] [-stop-on-vuln]")
                os.Exit(1)
        }

        reasons := strings.Split(*reasonsFlag, ",")
        for i, reason := range reasons {
                reasons[i] = strings.TrimSpace(reason)
        }

        if *excludeSizesFlag != "" {
                sizes := strings.Split(*excludeSizesFlag, ",")
                for _, size := range sizes {
                        excludeSizes = append(excludeSizes, atoi(size))
                }
        }
        if *excludeCodesFlag != "" {
                codes := strings.Split(*excludeCodesFlag, ",")
                for _, code := range codes {
                        excludeCodes = append(excludeCodes, atoi(code))
                }
        }

        if *outputFile != "" {
                var err error
                resultFile, err = os.Create(*outputFile)
                if err != nil {
                        fmt.Printf("%sError creating output file %s: %v%s\n", Red, *outputFile, err, Reset)
                        os.Exit(1)
                }
                defer resultFile.Close()
        }

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

        totalURLs := len(endpoints)
        totalPayloads := len(payloads)

        for i := 0; i < *threads; i++ {
                wg.Add(1)
                go worker(urlChan, payloads, *method, *reqInterval, &requestCount, &countMutex, &wg, *headers, *cookies, *timeout, *skipSSLVerify, totalURLs, totalPayloads, reasons)
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
        fmt.Printf("\n%s[+] Scan completed! Found: %d successful payloads%s\n", Green, successfulPayloads, Reset)
}

// atoi converts a string to an integer
func atoi(s string) int {
        i, err := strconv.Atoi(s)
        if err != nil {
                return 0
        }
        return i
}

// readLines reads a file and returns its lines as a slice of strings
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

// validateProxies validates the list of proxies
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

// extractParams extracts query parameters from a URL
func extractParams(endpoint string) map[string][]string {
        parsedURL, err := url.Parse(endpoint)
        if err != nil {
                return map[string][]string{}
        }
        return parsedURL.Query()
}

// buildURLWithParam builds a URL with a specific parameter and payload
func buildURLWithParam(endpoint, param, payload string) string {
        parsedURL, _ := url.Parse(endpoint)
        query := parsedURL.Query()
        query.Set(param, payload)
        parsedURL.RawQuery = query.Encode()
        return parsedURL.String()
}

// extractBaseEndpoint extracts the base endpoint from a URL
func extractBaseEndpoint(url string, payloads []string) string {
        for _, payload := range payloads {
                if strings.HasSuffix(url, payload) {
                        return strings.TrimSuffix(url, payload)
                }
        }
        return url
}

// createClient creates an HTTP client with the specified timeout and SSL verification settings
func createClient(timeout int, skipSSLVerify bool) *http.Client {
        transport := &http.Transport{
                ForceAttemptHTTP2: true,
                TLSClientConfig: &tls.Config{
                        InsecureSkipVerify: skipSSLVerify,
                },
        }
        if len(proxies) > 0 {
                proxyURL, _ := url.Parse(getNextProxy())
                transport.Proxy = http.ProxyURL(proxyURL)
        }
        return &http.Client{
                Timeout:   time.Duration(timeout) * time.Second,
                Transport: transport,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                },
        }
}

// getNextProxy returns the next proxy in the list
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

// buildRequest builds an HTTP request with the specified method, URL, payload, headers, and cookies
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

        // Add randomized realistic headers
        req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
        req.Header.Set("Accept", acceptOptions[rand.Intn(len(acceptOptions))])
        req.Header.Set("Accept-Language", acceptLanguageOptions[rand.Intn(len(acceptLanguageOptions))])
        req.Header.Set("Accept-Encoding", acceptEncodingOptions[rand.Intn(len(acceptEncodingOptions))])
        req.Header.Set("Connection", connectionOptions[rand.Intn(len(connectionOptions))])
        req.Header.Set("Cache-Control", cacheControlOptions[rand.Intn(len(cacheControlOptions))])
        req.Header.Set("Referer", refererOptions[rand.Intn(len(refererOptions))])
        req.Header.Set("X-Forwarded-For", randomIP())
        req.Header.Set("Forwarded", "for="+randomIP())

        // Simulate browser behavior with additional headers (optional)
        if rand.Intn(2) == 0 { // 50% chance
                req.Header.Set("DNT", "1") // Do Not Track
        }
        if rand.Intn(3) == 0 { // 33% chance
                req.Header.Set("Sec-Fetch-Site", "same-origin")
                req.Header.Set("Sec-Fetch-Mode", "navigate")
                req.Header.Set("Sec-Fetch-User", "?1")
                req.Header.Set("Sec-Fetch-Dest", "document")
        }

        return req, nil
}

// logResult logs a message to the result file if it is specified
func logResult(message string) {
        if resultFile != nil {
                resultMutex.Lock()
                defer resultMutex.Unlock()
                fmt.Fprintf(resultFile, "%s\n", message)
        }
}

// دالة مساعدة للتحقق من وجود String في Slice
func containsString(slice []string, item string) bool {
        for _, s := range slice {
                if s == item {
                        return true
                }
        }
        return false
}

// performRequestWithRetry performs an HTTP request with retries and exponential backoff
func performRequestWithRetry(req *http.Request, fullURL string, totalURLs int, totalPayloads int, currentURL int, currentPayload int, headers string, cookies string, reasons []string, timeout int, skipSSLVerify bool) (bool, int) {
        c := colly.NewCollector(
                colly.MaxDepth(1),
                colly.Async(false),
                colly.IgnoreRobotsTxt(),
        )

        transport := &http.Transport{
                ForceAttemptHTTP2: true,
                TLSClientConfig:   &tls.Config{InsecureSkipVerify: skipSSLVerify},
        }
        if len(proxies) > 0 {
                proxyURL, _ := url.Parse(getNextProxy())
                transport.Proxy = http.ProxyURL(proxyURL)
        }
        c.WithTransport(transport)

        c.SetRequestTimeout(time.Duration(timeout) * time.Second)

        var responseSize int
        var isVulnerable bool
        var body string

        c.OnRequest(func(r *colly.Request) {
                *r = colly.Request{
                        URL:     req.URL,
                        Method:  req.Method,
                        Body:    req.Body,
                        Headers: &req.Header,
                }
        })

        c.OnResponse(func(r *colly.Response) {
                responseSize = len(r.Body)
                body = string(r.Body)

                if responseSize == 0 || contains(excludeCodes, r.StatusCode) || contains(excludeSizes, responseSize) ||
                        r.StatusCode == http.StatusMovedPermanently || r.StatusCode == http.StatusFound ||
                        r.StatusCode == http.StatusSeeOther || r.StatusCode == http.StatusTemporaryRedirect ||
                        r.StatusCode == http.StatusPermanentRedirect || r.StatusCode == http.StatusBadRequest ||
                        r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden ||
                        r.StatusCode == http.StatusInternalServerError {
                        return
                }

                if r.StatusCode == http.StatusOK {
                        var reasonsList []string
                        indicatorsFound := false

                        if containsString(reasons, "indicators") {
                                for _, indicator := range indicators {
                                        if strings.Contains(body, indicator) {
                                                reasonsList = append(reasonsList, fmt.Sprintf("Found: %s", indicator))
                                                indicatorsFound = true
                                                isVulnerable = true
                                                break
                                        }
                                }
                        }

                        if indicatorsFound {
                                fmt.Printf("\r%s[+] LFI Detected (Indicators Found): %s \n       - | Reason: %s \033[34m| Response Size: \033[33m[ %d bytes ]%s\n\n", Green, fullURL, strings.Join(reasonsList, " | "), responseSize, Reset)
                                logResult(fmt.Sprintf("[+] LFI Detected (Indicators Found): %s | Reason: %s", fullURL, strings.Join(reasonsList, " | ")))
                                return
                        }

                        _, sizeWithoutPayload, statusCodeWithoutPayload, err := sendRequestWithoutPayload(nil, req.Method, fullURL, headers, cookies)
                        if err != nil || statusCodeWithoutPayload != http.StatusOK {
                                return
                        }

                        payloadSize := 0
                        if req.Method == "GET" {
                                parsedURL, _ := url.Parse(fullURL)
                                query := parsedURL.Query()
                                for _, values := range query {
                                        for _, value := range values {
                                                payloadSize += len(value)
                                        }
                                }
                        } else if req.Method == "POST" {
                                parts := strings.SplitN(fullURL, " ", 2)
                                if len(parts) == 2 {
                                        bodyPart := parts[1]
                                        payloadSize = len(bodyPart)
                                }
                        }

                        adjustedBodySize := responseSize - payloadSize
                        if adjustedBodySize < 0 {
                                adjustedBodySize = 0
                        }
                        sizeDifferencePercent := float64(adjustedBodySize-sizeWithoutPayload) / float64(sizeWithoutPayload) * 100
                        sizeDifferenceAbsolute := adjustedBodySize - sizeWithoutPayload

                        dummyURL := buildURLWithParam(fullURL, "dummy", "test0123")
                        _, dummySize, dummyStatusCode, err := sendRequestWithoutPayload(nil, req.Method, dummyURL, headers, cookies)
                        if err != nil || dummyStatusCode != http.StatusOK {
                                return
                        }

                        if containsString(reasons, "size") {
                                if sizeDifferenceAbsolute > 200 && sizeDifferencePercent > 25 {
                                        reasonsList = append(reasonsList, fmt.Sprintf("Size Diff: %.2f%%", sizeDifferencePercent))
                                        isVulnerable = true
                                } else if sizeDifferencePercent > 50 {
                                        reasonsList = append(reasonsList, fmt.Sprintf("Size Diff: %.2f%%", sizeDifferencePercent))
                                        isVulnerable = true
                                }
                        }

                        if isVulnerable {
                                topReasons := strings.Join(reasonsList, " | ")
                                fmt.Printf("\r%s[+] LFI Detected: %s \n       - | Reason: %s \033[34m| Sizes: [Req1: %d | Req2: %d | Req3: %d bytes]%s\n", Green, fullURL, topReasons, responseSize, sizeWithoutPayload, dummySize, Reset)
                                logResult(fmt.Sprintf("[+] LFI Detected: %s \n       - | Reason: %s | Sizes: [Req1: %d | Req2: %d | Req3: %d bytes]", fullURL, topReasons, responseSize, sizeWithoutPayload, dummySize))
                                return
                        }

                        sizeDiffBaselineVsDummy := abs(sizeWithoutPayload - dummySize)
                        sizeDiffBaselineVsDummyPercent := float64(sizeDiffBaselineVsDummy) / float64(sizeWithoutPayload) * 100
                        sizeDiffWithBaseline := abs(responseSize - sizeWithoutPayload)
                        sizeDiffWithDummyNew := abs(responseSize - dummySize)

                        if sizeDiffBaselineVsDummyPercent < 10 && (sizeDiffWithBaseline > 200 || sizeDiffWithDummyNew > 200) {
                                reasonsList = append(reasonsList, fmt.Sprintf("Baseline vs Dummy Size Diff: %.2f%% | Large Diff with Original: %d/%d bytes", sizeDiffBaselineVsDummyPercent, sizeDiffWithBaseline, sizeDiffWithDummyNew))
                                fmt.Printf("\r%s[+] LFI Detected: %s \n       - | Reason: %s \033[34m| Sizes: [Req1: %d | Req2: %d | Req3: %d bytes]%s\n", Green, fullURL, strings.Join(reasonsList, " | "), responseSize, sizeWithoutPayload, dummySize, Reset)
                                logResult(fmt.Sprintf("[+] LFI Detected: %s \n       - | Reason: %s | Sizes: [Req1: %d | Req2: %d | Req3: %d bytes]", fullURL, strings.Join(reasonsList, " | "), responseSize, sizeWithoutPayload, dummySize))
                                isVulnerable = true
                        }
                }
        })

        c.OnError(func(r *colly.Response, err error) {
                // بدون إعادة محاولة هنا، نعتمد على الـ limiter
        })

        err := c.Visit(fullURL) // محاولة واحدة بس
        if err != nil {
                return false, 0 // لو فشل، نرجع بدون تأخير
        }

        return isVulnerable, responseSize
}

// دالة مساعدة للحصول على القيمة المطلقة
func abs(x int) int {
        if x < 0 {
                return -x
        }
        return x
}

func worker(urlChan <-chan string, payloads []string, method string, reqInterval int, requestCount *int, countMutex *sync.Mutex, wg *sync.WaitGroup, headers string, cookies string, timeout int, skipSSLVerify bool, totalURLs int, totalPayloads int, reasons []string) {
        defer wg.Done()

        testedEndpoints := make(map[string]bool)
        rand.Seed(time.Now().UnixNano())

        for fullURL := range urlChan {
                if err := limiter.Wait(context.Background()); err != nil {
                        continue
                }
                time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond) // تأخير بسيط 0-10ms

                baseEndpoint := extractBaseEndpoint(fullURL, payloads)
                if testedEndpoints[baseEndpoint] {
                        continue
                }

                req, err := buildRequest(method, fullURL, payloads, headers, cookies)
                if err != nil {
                        continue
                }

                isVulnerable, _ := performRequestWithRetry(req, fullURL, totalURLs, totalPayloads, *requestCount+1, len(payloads), headers, cookies, reasons, timeout, skipSSLVerify)
                if isVulnerable {
                        successfulMutex.Lock()
                        successfulPayloads++
                        successfulMutex.Unlock()
                        if stopOnVuln {
                                testedEndpoints[baseEndpoint] = true
                        }
                }

                if showProgress {
                        countMutex.Lock()
                        currentRequest := *requestCount + 1
                        currentURL := (currentRequest-1)/totalPayloads + 1
                        currentPayload := (currentRequest-1)%totalPayloads + 1
                        fmt.Printf("\rURLs: %5d/%-5d | Payloads: %5d/%-5d | Found: %5d ",
                                currentURL, totalURLs, currentPayload, totalPayloads, successfulPayloads)
                        countMutex.Unlock()
                }

                countMutex.Lock()
                *requestCount++
                countMutex.Unlock()

                if *requestCount%reqInterval == 0 {
                        client := createClient(timeout, skipSSLVerify)
                        sendNormalRequest(client, baseEndpoint)
                }
        }
}

// sendRequestWithoutPayload sends a request without any payload
func sendRequestWithoutPayload(_ *http.Client, method, fullURL string, headers string, cookies string) (string, int, int, error) {
        c := colly.NewCollector(
                colly.MaxDepth(1),
                colly.Async(false),
                colly.IgnoreRobotsTxt(),
        )

        // ضبط الـ Transport لدعم البروكسيات وتخطي التحقق من SSL
        transport := &http.Transport{
                ForceAttemptHTTP2: true,
                TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // افتراضيًا بنخليها true، ممكن نعدلها لو لازم
        }
        if len(proxies) > 0 {
                proxyURL, _ := url.Parse(getNextProxy())
                transport.Proxy = http.ProxyURL(proxyURL)
        }
        c.WithTransport(transport)

        var body string
        var size, statusCode int

        c.OnRequest(func(r *colly.Request) {
                r.Method = method
                parsedURL, _ := url.Parse(fullURL)
                r.URL = parsedURL
                if headers != "" {
                        headerPairs := strings.Split(headers, ",")
                        for _, pair := range headerPairs {
                                parts := strings.SplitN(pair, ":", 2)
                                if len(parts) == 2 {
                                        r.Headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
                                }
                        }
                }
                if cookies != "" {
                        r.Headers.Set("Cookie", cookies)
                }
                r.Headers.Set("Cache-Control", "no-cache")
                r.Headers.Set("Pragma", "no-cache")
                r.Headers.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
                r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                r.Headers.Set("X-Forwarded-For", randomIP())
        })

        c.OnResponse(func(r *colly.Response) {
                body = string(r.Body)
                size = len(r.Body)
                statusCode = r.StatusCode
        })

        err := c.Visit(fullURL)
        if err != nil {
                return "", 0, 0, err
        }

        return body, size, statusCode, nil
}

// normalizeResponse removes dynamic content (like dates and times) from the response

func normalizeResponse(body string) string {
        body = strings.ReplaceAll(body, "\n", "")
        body = strings.ReplaceAll(body, "\r", "")
        body = strings.ReplaceAll(body, " ", "")
        // تنظيف التواريخ والأوقات
        re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}`)
        body = re.ReplaceAllString(body, "")
        // تنظيف معرفات الجلسات أو الأرقام العشوائية
        reSession := regexp.MustCompile(`[a-fA-F0-9]{32,64}`)
        body = reSession.ReplaceAllString(body, "")
        // تنظيف أرقام عشوائية طويلة (مثل CSRF tokens)
        reRandom := regexp.MustCompile(`\d{10,}`)
        body = reRandom.ReplaceAllString(body, "")
        return body
}

// sendNormalRequest sends a normal request to the base URL
func sendNormalRequest(client *http.Client, baseURL string) {
        req, err := http.NewRequest("GET", baseURL, nil)
        if err != nil {
                return
        }
        req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        resp, err := client.Do(req)
        if err != nil {

                /*fmt.Printf("\r%s[-] Error Detected: %s%s\n", Red, baseURL, Reset)*/
                return
        }
        resp.Body.Close()
}

// testCookies tests cookies with different payloads
func testCookies(fullURL string, payloads []string, client *http.Client, testedEndpoints map[string]bool, totalURLs int, totalPayloads int, reasons []string) {
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

                // استدعاء performRequestWithRetry بالمعاملات الجديدة
                isVulnerable, _ := performRequestWithRetry(req, fullURL, totalURLs, totalPayloads, 0, 0, "", "", reasons, 10, false) // timeout و skipSSLVerify هنا افتراضيين
                if isVulnerable {
                        testedEndpoints[baseURL] = true
                }
        }
}

// randomIP generates a random IP address
func randomIP() string {
        return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

// contains checks if a slice contains a specific item
func contains(slice []int, item int) bool {
        for _, s := range slice {
                if s == item {
                        return true
                }
        }
        return false
}
