package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
)

type httpFetchResult struct {
	page HTTPPageResult
	body []byte
}

func (scanner *httpScanner) fetchPage(rawURL, originalHost string, allowedHosts map[string]bool, bodyLimit int64, analyze bool) (HTTPPageResult, []byte) {
	result := scanner.fetch(rawURL, originalHost, allowedHosts, bodyLimit)
	if analyze {
		result.page.Findings = append(result.page.Findings,
			evaluateHTTPPage(result.page, strings.HasPrefix(result.page.FinalURL, "https://"))...)
		result.page.Findings = deduplicateFindings(result.page.Findings)
	}
	return result.page, result.body
}

func (scanner *httpScanner) fetch(rawURL, originalHost string, allowedHosts map[string]bool, bodyLimit int64) httpFetchResult {
	page := HTTPPageResult{RequestedURL: rawURL, ContentLength: -1}
	current, err := url.Parse(rawURL)
	if err != nil {
		page.Error = fmt.Sprintf("HTTP request URL %q is invalid: %v", rawURL, err)
		return httpFetchResult{page: page}
	}
	initialHost, err := normalizedURLHost(current)
	if err != nil || initialHost != originalHost {
		page.Error = fmt.Sprintf("HTTP request URL %q does not use original hostname %q", rawURL, originalHost)
		return httpFetchResult{page: page}
	}
	visited := make(map[string]bool)

	for {
		currentURL := canonicalURL(current)
		if visited[currentURL] {
			page.Error = fmt.Sprintf("redirect loop detected at %s", currentURL)
			page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LOOP", "warning",
				fmt.Sprintf("%s entered a redirect loop at %s.", rawURL, currentURL)))
			page.FinalURL = currentURL
			return httpFetchResult{page: page}
		}
		visited[currentURL] = true

		response, remoteIP, err := scanner.doSingleRequest(current)
		if err != nil {
			page.FinalURL = currentURL
			page.Error = fmt.Sprintf("GET %s: %v", currentURL, err)
			if errors.Is(err, errHTTPAddressBlocked) {
				page.Findings = append(page.Findings, finding("HTTP_TARGET_ADDRESS_BLOCKED", "info",
					fmt.Sprintf("%s was not requested because %v.", currentURL, err)))
			}
			return httpFetchResult{page: page}
		}

		page.FinalURL = currentURL
		page.StatusCode = response.StatusCode
		page.HTTPProtocol = response.Proto
		page.RemoteIP = remoteIP
		page.ContentType = response.Header.Get("Content-Type")
		page.ContentLength = response.ContentLength
		page.SecurityHeaders = observeSecurityHeaders(response.Header)
		page.Cookies = observeCookies(response.Header.Values("Set-Cookie"))

		if isRedirectStatus(response.StatusCode) {
			location := response.Header.Get("Location")
			closeResponseBody(response.Body)
			hop := RedirectHop{FromURL: currentURL, StatusCode: response.StatusCode, Location: redactURLUserinfo(location)}
			if location == "" {
				hop.StopReason = "missing_location"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Error = fmt.Sprintf("redirect response %s had no Location header", currentURL)
				return httpFetchResult{page: page}
			}
			next, err := current.Parse(location)
			if err != nil {
				hop.StopReason = "malformed_location"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Error = fmt.Sprintf("redirect from %s had malformed Location %q: %v", currentURL, location, err)
				return httpFetchResult{page: page}
			}
			next.Fragment = ""
			hop.ResolvedURL = redactURLUserinfo(canonicalURL(next))
			if next.Scheme != "http" && next.Scheme != "https" {
				hop.StopReason = "unsupported_scheme"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_UNSUPPORTED_SCHEME", "warning",
					fmt.Sprintf("%s redirected to unsupported scheme %q at %s.", currentURL, next.Scheme, hop.ResolvedURL)))
				return httpFetchResult{page: page}
			}
			if next.User != nil || !allowedHTTPPort(next) {
				hop.StopReason = "disallowed_url"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Error = fmt.Sprintf("redirect from %s used userinfo or a disallowed port in %s", currentURL, hop.ResolvedURL)
				return httpFetchResult{page: page}
			}
			nextHost, err := normalizedURLHost(next)
			if err != nil {
				hop.StopReason = "invalid_hostname"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Error = fmt.Sprintf("redirect from %s has an invalid hostname: %v", currentURL, err)
				return httpFetchResult{page: page}
			}
			if current.Scheme == "https" && next.Scheme == "http" {
				hop.StopReason = "insecure_downgrade"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_TO_INSECURE", "critical",
					fmt.Sprintf("%s redirected secure content to cleartext URL %s.", currentURL, hop.ResolvedURL)))
				return httpFetchResult{page: page}
			}
			if !allowedHosts[nextHost] {
				hop.StopReason = "out_of_scope"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_OUT_OF_SCOPE", "info",
					fmt.Sprintf("%s redirected to out-of-scope hostname %s; the redirect was recorded but not followed.", currentURL, nextHost)))
				return httpFetchResult{page: page}
			}
			if visited[hop.ResolvedURL] {
				hop.StopReason = "loop"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LOOP", "warning",
					fmt.Sprintf("%s entered a redirect loop at %s.", rawURL, hop.ResolvedURL)))
				return httpFetchResult{page: page}
			}
			if len(page.RedirectChain) >= scanner.options.MaxRedirects {
				hop.StopReason = "redirect_limit"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LIMIT_REACHED", "warning",
					fmt.Sprintf("%s reached the configured redirect limit of %d at %s.", rawURL, scanner.options.MaxRedirects, currentURL)))
				return httpFetchResult{page: page}
			}
			hop.Followed = true
			page.RedirectChain = append(page.RedirectChain, hop)
			current = next
			continue
		}

		body, bytesRead, truncated, readErr := readAndCloseBody(response.Body, bodyLimit)
		page.BytesRead = bytesRead
		page.BodyTruncated = truncated
		if readErr != nil {
			page.Error = fmt.Sprintf("reading response body from %s: %v", currentURL, readErr)
		}
		return httpFetchResult{page: page, body: body}
	}
}

var errHTTPAddressBlocked = errors.New("HTTP target address blocked")

func (scanner *httpScanner) doSingleRequest(target *url.URL) (*http.Response, string, error) {
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, "", fmt.Errorf("unsupported URL scheme %q", target.Scheme)
	}
	if !allowedHTTPPort(target) {
		return nil, "", fmt.Errorf("port %q is not permitted", target.Port())
	}
	host, err := normalizedURLHost(target)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanner.options.Timeout)
	addresses, err := scanner.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		cancel()
		return nil, "", fmt.Errorf("resolving %s: %w", host, err)
	}
	if len(addresses) == 0 {
		cancel()
		return nil, "", fmt.Errorf("resolving %s returned no addresses", host)
	}
	ips := sortedIPs(addresses)
	for _, ip := range ips {
		if blockedHTTPAddress(ip) {
			cancel()
			return nil, "", fmt.Errorf("%w: %s resolved to %s", errHTTPAddressBlocked, host, ip.String())
		}
	}

	port := httpURLPort(target)
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: maxHTTPResponseHeaders,
		TLSHandshakeTimeout:    scanner.options.Timeout,
		ResponseHeaderTimeout:  scanner.options.Timeout,
		ExpectContinueTimeout:  0,
		TLSClientConfig:        &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	if scanner.tlsConfig != nil {
		transport.TLSClientConfig = scanner.tlsConfig.Clone()
		transport.TLSClientConfig.ServerName = host
	}
	transport.DialContext = func(dialContext context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		for _, ip := range ips {
			conn, err := scanner.dialer.DialContext(dialContext, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		cancel()
		return nil, "", err
	}
	request.Header.Set("User-Agent", "mpdc/"+version)
	remoteIP := ""
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if address, ok := info.Conn.RemoteAddr().(*net.TCPAddr); ok {
				remoteIP = address.IP.String()
			} else {
				host, _, splitErr := net.SplitHostPort(info.Conn.RemoteAddr().String())
				if splitErr == nil {
					remoteIP = host
				}
			}
		},
	}))
	response, err := client.Do(request)
	if err != nil {
		cancel()
		transport.CloseIdleConnections()
		return nil, remoteIP, err
	}
	response.Body = &cancelOnCloseBody{ReadCloser: response.Body, cancel: cancel}
	return response, remoteIP, nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnCloseBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func redactURLUserinfo(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return value
	}
	parsed.User = url.User("[redacted]")
	return parsed.String()
}

func readAndCloseBody(body io.ReadCloser, limit int64) ([]byte, int64, bool, error) {
	defer body.Close()
	reader := io.LimitReader(body, limit+1)
	data, err := io.ReadAll(reader)
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return data, int64(len(data)), truncated, err
}

func closeResponseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_ = body.Close()
}
