package main

import (
    "bufio"
    "bytes"
    "flag"
    "fmt"
    "io/ioutil"
    "math/rand"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

// ANSI color codes
const (
    Red    = "\033[31m"
    White  = "\033[37m"
    Reset  = "\033[0m"
    Yellow = "\033[33m"
)

// LFI indicators to check in responses
var lfiIndicators = []string{
    "root",
    "/bin/bash",
    "/usr/sbin",
    "/var/www",
    "/var/lib",
}

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

var proxies []string

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
[!] Legal disclaimer: Usage of YLfi for attacking targets without prior mutual consent
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
    flag.Parse()

    if *payloadFile == "" || (*urlFlag == "" && *endpointFile == "") {
        fmt.Println("Usage: go run YLfi.go -p payloads.txt [-u url/request_file | -f endpoints.txt] [-t threads] [-m GET|POST] [-r interval] [-proxy proxy | -proxyfile proxies_file]")
        os.Exit(1)
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
        go worker(urlChan, payloads, *method, *reqInterval, &requestCount, &countMutex, &wg)
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

func worker(urlChan <-chan string, payloads []string, method string, reqInterval int, requestCount *int, countMutex *sync.Mutex, wg *sync.WaitGroup) {
    defer wg.Done()

    testedEndpoints := make(map[string]bool)
    rand.Seed(time.Now().UnixNano())
    client := createClient()

    for fullURL := range urlChan {
        baseEndpoint := extractBaseEndpoint(fullURL, payloads)
        if testedEndpoints[baseEndpoint] {
            continue
        }

        req, err := buildRequest(method, fullURL, payloads)
        if err != nil {
            fmt.Printf("%s[-] Error building request for %s: %v%s\n", Red, fullURL, err, Reset)
            continue
        }

        for attempt := 1; attempt <= 2; attempt++ {
            resp, err := client.Do(req)
            if err != nil {
                fmt.Printf("%s[-] Error on %s (attempt %d): %v%s\n", Red, fullURL, attempt, err, Reset)
                if attempt == 2 {
                    break
                }
                time.Sleep(1 * time.Second)
                continue
            }
            defer resp.Body.Close()

            body, err := ioutil.ReadAll(resp.Body)
            if err != nil {
                fmt.Printf("%s[-] Error reading response body from %s: %v%s\n", Red, fullURL, err, Reset)
                break
            }

            bodyStr := string(body)
            for _, indicator := range lfiIndicators {
                if strings.Contains(bodyStr, indicator) {
                    fmt.Printf("%s[+] Potential LFI found: %s%s\n", Green, fullURL, Reset)
                    fmt.Printf("%s    Indicator: %s%s\n", Green, indicator, Reset)
                    testedEndpoints[baseEndpoint] = true
                    break
                }
            }
            break
        }

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

func createClient() *http.Client {
    transport := &http.Transport{
        ForceAttemptHTTP2: false,
    }
    if len(proxies) > 0 {
        proxyURL, _ := url.Parse(proxies[rand.Intn(len(proxies))])
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    return &http.Client{
        Timeout:   10 * time.Second,
        Transport: transport,
    }
}

func buildRequest(method, fullURL string, payloads []string) (*http.Request, error) {
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

        resp, err := client.Do(req)
        if err != nil {
            fmt.Printf("%s[-] Error testing cookie on %s: %v%s\n", Red, fullURL, err, Reset)
            continue
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            continue
        }

        bodyStr := string(body)
        for _, indicator := range lfiIndicators {
            if strings.Contains(bodyStr, indicator) {
                fmt.Printf("%s[+] Potential LFI found in cookie: %s (Cookie: test=%s)%s\n", Green, fullURL, payload, Reset)
                fmt.Printf("%s    Indicator: %s%s\n", Green, indicator, Reset)
                testedEndpoints[baseURL] = true
                break
            }
        }
    }
}

func randomIP() string {
    return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
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
