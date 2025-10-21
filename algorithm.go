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
	// AlgDefault is the default algorithm, which is HMAC-SHA1 for TOTP.
	AlgDefault Algorithm = iota
	// AlgHmacSha1 is the HMAC-SHA1 algorithm.
	AlgHmacSha1
	// AlgHmacSha256 is the HMAC-SHA256 algorithm.
	AlgHmacSha256
	// AlgHmacSha512 is the HMAC-SHA512 algorithm.
	AlgHmacSha512
)

// String returns the string representation of the Algorithm.
func (a Algorithm) String() string {
	switch a {
	case AlgHmacSha256:
		return "SHA256"
	case AlgHmacSha512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

// getHashFunc returns the hash function corresponding to the given algorithm.
func getHashFunc(algorithm Algorithm) (func() hash.Hash, error) {
	switch algorithm {
	case AlgHmacSha1:
		return sha1.New, nil
	case AlgHmacSha256:
		return sha256.New, nil
	case AlgHmacSha512:
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
