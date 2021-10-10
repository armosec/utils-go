package utils

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
)

//AsSHA256 takes anything turns it into string :) https://blog.8bitzen.com/posts/22-08-2019-how-to-hash-a-struct-in-go
func AsSHA256(v interface{}) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", v)))

	return fmt.Sprintf("%x", h.Sum(nil))
}

//AsFNVHash takes anything turns it into string :) https://blog.8bitzen.com/posts/22-08-2019-how-to-hash-a-struct-in-go
func AsFNVHash(v interface{}) string {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%v", v)))
	return fmt.Sprintf("%d", h.Sum32())
}
