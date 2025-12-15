package otp

import (
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"strconv"
)

// generateOTP generates a one-time password using the provided HMAC hash function, message, and
// number of digits.
func generateOTP(hashFunc hash.Hash, msg []byte, digits int) (string, error) {
	if _, err := hashFunc.Write(msg); err != nil {
		return "", err
	}

	hash := hashFunc.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F
	val := ((uint64(hash[offset]) & 0x7F) << 24) |
		((uint64(hash[offset+1]) & 0xFF) << 16) |
		((uint64(hash[offset+2]) & 0xFF) << 8) |
		(uint64(hash[offset+3]) & 0xFF)

	return encode(val, digits), nil
}

func getOTPURI(
	otpType, accountName, issuer string,
	secret []byte,
	algorithm Algorithm,
	digits int,
	periodOrCounter int64,
) (string, error) {
	rawPath := url.QueryEscape(accountName)
	if issuer != "" {
		rawPath = url.PathEscape(issuer) + ":" + rawPath
	}

	query := url.Values{}
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	query.Set("secret", encodedSecret)

	if issuer != "" {
		query.Set("issuer", issuer)
	}

	if algorithm != AlgHmacSha1 {
		query.Set("algorithm", algorithm.String())
	}

	if digits != 6 {
		query.Set("digits", strconv.Itoa(digits))
	}

	switch otpType {
	case "totp":
		if periodOrCounter != 30 {
			query.Set("period", strconv.FormatInt(periodOrCounter, 10))
		}
	case "hotp":
		query.Set("counter", strconv.FormatInt(periodOrCounter, 10))
	}

	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, rawPath, query.Encode()), nil
}
