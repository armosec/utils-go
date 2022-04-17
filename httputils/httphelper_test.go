package shared

import (
	"net/http"
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
