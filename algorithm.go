package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Algorithm represents the hashing algorithm used in OTP generation.
type Algorithm int

const (
	// HmacSha1 is the HMAC-SHA1 algorithm.
	HmacSha1 Algorithm = iota
	// HmacSha256 is the HMAC-SHA256 algorithm.
	HmacSha256
	// HmacSha512 is the HMAC-SHA512 algorithm.
	HmacSha512
)

// getHashFunc returns the hash function corresponding to the given algorithm.
func getHashFunc(algorithm Algorithm) (func() hash.Hash, error) {
	switch algorithm {
	case HmacSha1:
		return sha1.New, nil
	case HmacSha256:
		return sha256.New, nil
	case HmacSha512:
		return sha512.New, nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// getHash returns a new HMAC hash.Hash using the specified algorithm and secret.
func getHash(algorithm Algorithm, secret []byte) (hash.Hash, error) {
	hashFunc, err := getHashFunc(algorithm)
	if err != nil {
		return nil, err
	}

	return hmac.New(hashFunc, secret), nil
}
