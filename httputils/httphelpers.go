package httputils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
)

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ShouldNotRetryFunc func(resp *http.Response) bool

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpDelete(httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	return HttpDeleteWithContext(context.Background(), httpClient, fullURL, headers)
}

func HttpDeleteWithContext(ctx context.Context, httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", fullURL, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}

func HttpHead(httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	return HttpHeadWithContext(context.Background(), httpClient, fullURL, headers)
}

func HttpHeadWithContext(ctx context.Context, httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", fullURL, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}

func HttpGet(httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	return HttpGetWithContext(context.Background(), httpClient, fullURL, headers)
}

func HttpGetWithContext(ctx context.Context, httpClient IHttpClient, fullURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, headers)

	return httpClient.Do(req)
}

func HttpPost(httpClient IHttpClient, fullURL string, headers map[string]string, body []byte) (*http.Response, error) {
	return HttpPostWithContext(context.Background(), httpClient, fullURL, headers, body, -1, func(resp *http.Response) bool {
		return true
	})
}

func HttpPostWithRetry(httpClient IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration) (*http.Response, error) {
	return HttpPostWithContext(context.Background(), httpClient, fullURL, headers, body, maxElapsedTime, defaultShouldRetry)
}

func HttpPostWithContext(ctx context.Context, httpClient IHttpClient, fullURL string, headers map[string]string, body []byte, maxElapsedTime time.Duration, shouldRetry func(resp *http.Response) bool) (*http.Response, error) {
	var resp *http.Response
	var err error

	operation := func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewReader(body))
		if err != nil {
			fmt.Println("Error creating request")
			return backoff.Permanent(err)
		}
		setHeaders(req, headers)

		resp, err = httpClient.Do(req)
		if err != nil {
			fmt.Println("Error sending request")
			return err
		}
		defer resp.Body.Close()

		// If the status code is not 200, we will retry
		if resp.StatusCode != http.StatusOK {
			if shouldRetry(resp) {
				return fmt.Errorf("received status code: %d", resp.StatusCode)
			}
			return backoff.Permanent(err)
		}

		return nil
	}

	// Create a new exponential backoff policy
	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.MaxElapsedTime = maxElapsedTime // Set the maximum elapsed time

	// Run the operation with the exponential backoff policy
	if err = backoff.Retry(operation, expBackOff); err != nil {
		fmt.Print("Error sending request 2")
		return resp, err
	}
	fmt.Println("Success sending request")
	return resp, nil
}
func defaultShouldRetry(resp *http.Response) bool {
	// If received codes 401/403/404/500 should return false
	return resp.StatusCode != http.StatusUnauthorized &&
		resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != http.StatusInternalServerError
}

func setHeaders(req *http.Request, headers map[string]string) {
	if len(headers) > 0 {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
}

// HttpRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
func HttpRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
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

func Split2Chunks[T any](maxNumOfChunks int, slice []T) [][]T {
	var divided [][]T
	if len(slice) <= maxNumOfChunks {
		for _, v := range slice {
			divided = append(divided, []T{v})
		}
		return divided
	}

	for i := 0; i < maxNumOfChunks; i++ {
		min := (i * len(slice) / maxNumOfChunks)
		max := ((i + 1) * len(slice)) / maxNumOfChunks
		divided = append(divided, slice[min:max])
	}
	return divided
}

// SplitSlice2Chunks - *recursively* splits a slice to chunks of sub slices that do not exceed max bytes size
// Returns a channels for receiving []T chunks and the original len of []T
// If []T is empty the function will return a closed chunks channel
// Chunks might be bigger than max size if the slice contains element(s) that are bigger than the max size
// this split algorithm fits for slices with elements that share more or less the same size per element
// uses optimistic average size splitting to enhance performance and reduce the use of json encoding for size calculations
// chunks channel will be closed after splitting is done
func SplitSlice2Chunks[T any](slice []T, maxSize int, channelBuffer int) (chunksChannel <-chan []T, sliceSize int) {
	channel := make(chan []T, channelBuffer)
	sliceSize = len(slice)
	if sliceSize > 0 {
		go func(chunksChannel chan<- []T) {
			splitWg := &sync.WaitGroup{}
			splitSlice2Chunks(slice, maxSize, chunksChannel, splitWg)
			splitWg.Wait()
			close(chunksChannel)
		}(channel)
	} else {
		close(channel)
	}
	chunksChannel = channel
	return chunksChannel, sliceSize
}

func splitSlice2Chunks[T any](slice []T, maxSize int, chunks chan<- []T, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(slice []T, maxSize int, chunks chan<- []T, wg *sync.WaitGroup) {
		defer wg.Done()
		if len(slice) < 2 {
			//cannot split if the slice is empty or has one element
			chunks <- slice
			return
		}
		//check slice size
		jsonSize := JSONSize(slice)
		if jsonSize <= maxSize {
			//slice size is smaller than max size no splitting needed
			chunks <- slice
			return
		}
		//slice is bigger than max size
		//split the slice to slices smaller than max size
		index := 0
		for i, _ := range slice {
			jsonSize = JSONSize(slice[index : i+1])
			if jsonSize > maxSize {
				//send the part of the slice that is smaller than max size
				splitSlice2Chunks(slice[index:i], maxSize, chunks, wg)
				index = i
			}
		}
		//send the last part of the slice
		splitSlice2Chunks(slice[index:], maxSize, chunks, wg)
	}(slice, maxSize, chunks, wg)
}

// JSONSize returns the size in bytes of the json encoding of i
func JSONSize(i interface{}) int {
	if i == nil {
		return 0
	}
	counter := bytesCounter{}
	enc := json.NewEncoder(&counter)
	err := enc.Encode(i)
	if err != nil {
		return 0
	}
	return counter.count
}

// bytesCounter - dummy io writer that just counts bytes without writing
type bytesCounter struct {
	count int
}

func (bc *bytesCounter) Write(p []byte) (n int, err error) {
	pSize := len(p)
	bc.count += pSize
	return pSize, nil
}
