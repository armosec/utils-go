package shared

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpDelete(httpClient *http.Client, fullURL string, headers map[string]string) (*http.Response, error) {

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}
func HttpGet(httpClient *http.Client, fullURL string, headers map[string]string) (*http.Response, error) {

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}

func HttpPost(httpClient *http.Client, fullURL string, headers map[string]string, body []byte) (*http.Response, error) {

	req, err := http.NewRequest("POST", fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}

func setHeaders(req *http.Request, headers map[string]string) {
	if len(headers) > 0 { // might be nil
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
func HttpRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	_, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
		// return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, respStr[:respStrNewLen])
	}

	return respStr, err
}
