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

func (scanner *httpScanner) fetchPage(ctx context.Context, rawURL, originalHost string, allowedHosts map[string]bool, bodyLimit int64, analyze bool) (HTTPPageResult, []byte) {
	result := scanner.fetch(ctx, rawURL, originalHost, allowedHosts, bodyLimit)
	if analyze {
		result.page.Findings = append(result.page.Findings,
			evaluateHTTPPage(result.page, strings.HasPrefix(result.page.FinalURL, "https://"))...)
	}
	result.page.Findings = deduplicateFindings(result.page.Findings)
	return result.page, result.body
}

func (scanner *httpScanner) fetch(ctx context.Context, rawURL, originalHost string, allowedHosts map[string]bool, bodyLimit int64) httpFetchResult {
	page := HTTPPageResult{RequestedURL: redactURLForOutput(rawURL), ContentLength: -1}
	current, err := url.Parse(rawURL)
	if err != nil {
		page.Error = fmt.Sprintf("HTTP request URL %q is invalid: %v", page.RequestedURL, redactURLParseError(err, rawURL))
		return httpFetchResult{page: page}
	}
	initialHost, err := normalizedURLHost(current)
	if err != nil || initialHost != originalHost {
		page.Error = fmt.Sprintf("HTTP request URL %q does not use original hostname %q", page.RequestedURL, originalHost)
		return httpFetchResult{page: page}
	}
	visited := make(map[string]bool)

	for {
		currentURLRaw := canonicalURL(current)
		currentURL := redactURLForOutput(currentURLRaw)
		if visited[currentURLRaw] {
			page.Error = fmt.Sprintf("redirect loop detected at %s", currentURL)
			page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LOOP", "warning",
				fmt.Sprintf("%s entered a redirect loop at %s.", page.RequestedURL, currentURL)))
			page.FinalURL = currentURL
			page.finalURLRaw = currentURLRaw
			return httpFetchResult{page: page}
		}
		visited[currentURLRaw] = true

		response, remoteIP, err := scanner.doSingleRequest(ctx, current)
		if err != nil {
			page.FinalURL = currentURL
			page.finalURLRaw = currentURLRaw
			page.Error = fmt.Sprintf("GET %s: %v", currentURL, err)
			if errors.Is(err, errHTTPAddressBlocked) {
				page.Findings = append(page.Findings, finding("HTTP_TARGET_ADDRESS_BLOCKED", "info",
					fmt.Sprintf("%s was not requested because %v.", currentURL, err)))
			}
			return httpFetchResult{page: page}
		}

		page.FinalURL = currentURL
		page.finalURLRaw = currentURLRaw
		page.StatusCode = response.StatusCode
		page.HTTPProtocol = response.Proto
		page.RemoteIP = remoteIP
		page.ContentType = response.Header.Get("Content-Type")
		page.ContentLength = response.ContentLength
		page.SecurityHeaders = observeSecurityHeaders(response.Header)
		page.Cookies = observeCookies(response.Header.Values("Set-Cookie"))
		// Cookie attributes matter on redirects and error responses as well as 2xx pages.
		if current.Scheme == "https" {
			page.Findings = append(page.Findings, evaluateCookieFindings(currentURL, page.Cookies)...)
		}

		if isRedirectStatus(response.StatusCode) {
			location := response.Header.Get("Location")
			closeResponseBody(response.Body)
			hop := RedirectHop{FromURL: currentURL, StatusCode: response.StatusCode, Location: redactURLForOutput(location), Cookies: page.Cookies}
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
				page.Error = fmt.Sprintf("redirect from %s had malformed Location %q: %v", currentURL, hop.Location, redactURLParseError(err, location))
				return httpFetchResult{page: page}
			}
			next.Fragment = ""
			nextURLRaw := canonicalURL(next)
			hop.ResolvedURL = redactURLForOutput(nextURLRaw)
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
			if visited[nextURLRaw] {
				hop.StopReason = "loop"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LOOP", "warning",
					fmt.Sprintf("%s entered a redirect loop at %s.", page.RequestedURL, hop.ResolvedURL)))
				return httpFetchResult{page: page}
			}
			if len(page.RedirectChain) >= scanner.options.MaxRedirects {
				hop.StopReason = "redirect_limit"
				page.RedirectChain = append(page.RedirectChain, hop)
				page.Findings = append(page.Findings, finding("HTTP_REDIRECT_LIMIT_REACHED", "warning",
					fmt.Sprintf("%s reached the configured redirect limit of %d at %s.", page.RequestedURL, scanner.options.MaxRedirects, currentURL)))
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

// egressHTTPDialer is the final policy gate at the socket boundary. It accepts
// only literal, public IP addresses on the two permitted HTTP ports, even when
// a caller has already validated and pinned DNS results.
type egressHTTPDialer struct {
	next httpDialer
}

func (dialer egressHTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%w: network %q is not permitted", errHTTPAddressBlocked, network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid dial address", errHTTPAddressBlocked)
	}
	if port != "80" && port != "443" {
		return nil, fmt.Errorf("%w: port %q is not permitted", errHTTPAddressBlocked, port)
	}
	ip := net.ParseIP(host)
	if ip == nil || blockedHTTPAddress(ip) {
		return nil, fmt.Errorf("%w: dial address %q is not globally reachable", errHTTPAddressBlocked, host)
	}
	return dialer.next.DialContext(ctx, network, address)
}

func (scanner *httpScanner) doSingleRequest(ctx context.Context, target *url.URL) (*http.Response, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
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
	ctx, cancel := context.WithTimeout(ctx, scanner.options.Timeout)
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
	egressDialer := egressHTTPDialer{next: scanner.dialer}
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
			conn, err := egressDialer.DialContext(dialContext, network, net.JoinHostPort(ip.String(), port))
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
		return nil, remoteIP, redactedHTTPError{err: err, rawURL: target.String(), safeURL: redactURLForOutput(target.String())}
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

type redactedHTTPError struct {
	err     error
	rawURL  string
	safeURL string
}

func (err redactedHTTPError) Error() string {
	return strings.ReplaceAll(err.err.Error(), err.rawURL, err.safeURL)
}

func (err redactedHTTPError) Unwrap() error { return err.err }

func redactURLForOutput(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return redactRawURLQuery(value)
	}
	if parsed.User != nil {
		parsed.User = url.User("[redacted]")
	}
	parsed.RawQuery = redactRawQuery(parsed.RawQuery)
	return parsed.String()
}

func redactRawURLQuery(value string) string {
	beforeFragment, fragment, hasFragment := strings.Cut(value, "#")
	base, query, hasQuery := strings.Cut(beforeFragment, "?")
	if hasQuery {
		beforeFragment = base + "?" + redactRawQuery(query)
	}
	if hasFragment {
		return beforeFragment + "#" + fragment
	}
	return beforeFragment
}

func redactRawQuery(query string) string {
	if query == "" {
		return ""
	}
	var result strings.Builder
	for len(query) > 0 {
		separator := strings.IndexAny(query, "&;")
		parameter := query
		if separator >= 0 {
			parameter = query[:separator]
		}
		name, _, hasValue := strings.Cut(parameter, "=")
		result.WriteString(name)
		if hasValue {
			result.WriteString("=[redacted]")
		}
		if separator < 0 {
			break
		}
		result.WriteByte(query[separator])
		query = query[separator+1:]
	}
	return result.String()
}

func redactURLParseError(err error, rawURL string) string {
	return strings.ReplaceAll(err.Error(), rawURL, redactURLForOutput(rawURL))
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
