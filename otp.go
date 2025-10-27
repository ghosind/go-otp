package otp

import "hash"

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
