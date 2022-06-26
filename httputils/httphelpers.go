package httputils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
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

//SplitSlice2Chunks - *recursively* splits a slice to chunks of sub slices that do not exceed max bytes size
//Returns a channels for receiving []T chunks and the original len of []T
//If []T is empty the function will return a closed chunks channel
//Chunks might be bigger than max size if the slice contains element(s) that are bigger than the max size
//this split algorithm fits for slices with elements that share more or less the same size per element
//uses optimistic average size splitting to enhance performance and reduce the use of json encoding for size calculations
//chunks channel will be closed after splitting is done
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
		//calculate the average size + 5% of a single element T
		avgTSize := int(math.Round(float64(jsonSize) * 1.05 / float64(len(slice))))
		//calculate the average number of elements that will not exceed max size
		avgSliceSize := maxSize / avgTSize
		last := len(slice)
		if avgSliceSize >= last {
			avgSliceSize = last / 2
		} else if avgSliceSize < 1 {
			avgSliceSize = 1
		}

		//split the slice to slices of avgSliceSize size
		startIndex := 0
		for i := avgSliceSize; i < last; i += avgSliceSize {
			splitSlice2Chunks(slice[startIndex:i], maxSize, chunks, wg)
			startIndex = i
		}
		//send the last part of the slice
		splitSlice2Chunks(slice[startIndex:last], maxSize, chunks, wg)
	}(slice, maxSize, chunks, wg)
}

//jsonSize returns the size in bytes of the json encoding of i
func JSONSize(i interface{}) int {
	if i == nil {
		return 0
	}
	counter := bytesCounter{}
	enc := json.NewEncoder(&counter)
	enc.Encode(i)
	return counter.count
}

//bytesCounter - dummy io writer that just counts bytes without writing
type bytesCounter struct {
	count int
}

func (bc *bytesCounter) Write(p []byte) (n int, err error) {
	pSize := len(p)
	bc.count += pSize
	return pSize, nil
}
