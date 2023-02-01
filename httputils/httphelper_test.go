package httputils

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetHeaders(t *testing.T) {
	{
		req, _ := http.NewRequest("", "", nil)
		setHeaders(req, nil)
		assert.Equal(t, 0, len(req.Header))
	}
	{
		req, _ := http.NewRequest("", "", nil)
		setHeaders(req, map[string]string{"a": "aa", "b": "bb"})
		assert.Equal(t, 2, len(req.Header))
	}
}

func TestSplitSlice2Chunks(t *testing.T) {
	//dummy testStruct type
	type testStruct struct {
		Name string `json:"name"`
	}
	//testStruct type slice test case
	testTypeSlice := []testStruct{
		{
			Name: "CVE-2016-2781",
		},
		{
			Name: "CVE-2020-16156",
		},
		{
			Name: "CVE-2021-39537",
		},
		{
			Name: "CVE-2021-43618",
		},
		{
			Name: "CVE-2022-1304",
		},
		{
			Name: "CVE-2022-1586",
		},
		{
			Name: "CVE-2022-1587",
		},
		{
			Name: "CVE-2022-1664",
		},
		{
			Name: "CVE-2022-29458",
		},
		{
			Name: "CVE-2013-4235",
		},
		{
			Name: "CVE-2016-20013",
		},
		{
			Name: "CVE-2017-11164",
		},
		{
			Name: "CVE-2020-9794",
		},
		{
			Name: "CVE-2020-9849",
		},
		{
			Name: "CVE-2020-9991",
		},
		{
			Name: "CVE-2021-36222",
		},
		{
			Name: "CVE-2021-3671",
		},
		{
			Name: "CVE-2021-37750",
		},
		{
			Name: "CVE-2022-22747",
		},
		{
			Name: "CVE-2022-27404",
		},
		{
			Name: "CVE-2022-27405",
		},
		{
			Name: "CVE-2022-27406",
		},
		{
			Name: "CVE-2002-1647",
		},
		{
			Name: "CVE-2006-1611",
		},
		{
			Name: "CVE-2017-18589",
		},
		{
			Name: "CVE-2019-10743",
		},
		{
			Name: "CVE-2020-10743",
		},
		{
			Name: "CVE-2020-7753",
		},
		{
			Name: "CVE-2021-29940",
		},
		{
			Name: "CVE-2021-3749",
		},
		{
			Name: "CVE-2022-0323",
		},
		{
			Name: "GHSA-cph5-m8f7-6c5x",
		},
		{
			Name: "GHSA-pgw7-wx7w-2w33",
		},
	}

	//split splice to chunks
	chunksChan, totalTestTypes := SplitSlice2Chunks(testTypeSlice, 100, 10)
	testWg := sync.WaitGroup{}
	var totalReceived, numOfChunks, maxChunkSize, minChunkSize, maxChunkLength, minChunkLength int
	testWg.Add(1)
	go func() {
		defer testWg.Done()
		for v := range chunksChan {
			fmt.Println(v)
			numOfChunks++
			vSize := JSONSize(v)
			vLen := len(v)
			totalReceived += vLen
			if maxChunkSize < vSize {
				maxChunkSize = vSize
			}
			if minChunkSize > vSize || minChunkSize == 0 {
				minChunkSize = vSize
			}
			if maxChunkLength < vLen {
				maxChunkLength = vLen
			}
			if minChunkLength > vLen || minChunkLength == 0 {
				minChunkLength = vLen
			}
		}
	}()
	//wait for all chunks to arrive
	testWg.Wait()
	//compare with expected
	assert.Equal(t, totalTestTypes, totalReceived, "total elements received is not equal to number of element sent")
	assert.Equal(t, 3, minChunkLength, "minChunkLength must be same as expected minChunkLength")
	assert.Equal(t, 3, maxChunkLength, "maxChunkLength must be same as expected maxChunkLength")
	assert.Equal(t, 77, minChunkSize, "minChunkSize must be same as expected minChunkSize")
	assert.Equal(t, 89, maxChunkSize, "maxChunkSize must be same as expected maxChunkSize")
	assert.Equal(t, 11, numOfChunks, "numOfChunks must be same as expected numOfChunks")

}

func TestSplit2Chunks(t *testing.T) {
	type args struct {
		maxNumOfChunks int
		slice          []string
	}
	tests := []struct {
		name string
		args args
		want [][]string
	}{
		{
			name: "TestSplit2Chunks1",
			args: args{
				maxNumOfChunks: 3,
				slice:          []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			},
			want: [][]string{{"a", "b", "c"}, {"d", "e", "f"}, {"g", "h", "i", "j"}},
		},
		{
			name: "TestSplit2Chunks2",
			args: args{
				maxNumOfChunks: 10,
				slice:          []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			},
			want: [][]string{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}, {"f"}, {"g"}, {"h"}, {"i"}, {"j"}},
		},
		{
			name: "TestSplit2Chunks3",

			args: args{
				maxNumOfChunks: 1,
				slice:          []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			},
			want: [][]string{{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Split2Chunks(tt.args.maxNumOfChunks, tt.args.slice); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Split2Chunks() = %v, want %v", got, tt.want)
			}
		})
	}

}
