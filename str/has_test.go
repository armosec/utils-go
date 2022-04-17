package str

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type object struct {
	a string
	b bool
	c interface{}
}

func TestAsSHA256(t *testing.T) {
	o := object{
		a: "aaa",
		b: true,
		c: object{
			a: "ooop",
		},
	}
	assert.Equal(t, "0afe3bec0a40a0d63fb0a570f3fffb572e46b6e0fb4a1eda8d8c055903d121c6", AsSHA256(o))

	o.b = false
	assert.Equal(t, "0a9659419d14f92700f028dffa8b7a9a50686c0278a4846b082c89a2b45f5faf", AsSHA256(o))

}

func TestAsFNVHash(t *testing.T) {
	o := object{
		a: "aaa",
		b: true,
		c: object{
			a: "ooop",
		},
	}
	assert.Equal(t, "1583525587", AsFNVHash(o))

	o.b = false
	assert.Equal(t, "848808146", AsFNVHash(o))

}
