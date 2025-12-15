package otp

import "encoding/binary"

const (
	defaultHOTPDigits = 6
)

// HOTP is HMAC-based One-Time Password algorithm implementation.
type HOTP struct {
	digits int
}

// NewHOTP creates a new HOTP instance with the given options.
func NewHOTP(opts ...Option) *HOTP {
	builder := new(otpBuilder)
	for _, opt := range opts {
		opt(builder)
	}

	return &HOTP{
		digits: builder.digits,
	}
}

// Digits returns the number of digits in the generated HOTP. If not set, it defaults to 6.
func (h *HOTP) Digits() int {
	if h.digits <= 0 || h.digits > 8 {
		return defaultHOTPDigits
	}
	return h.digits
}

// Generate generates an HOTP using the provided secret key and counter.
func (h *HOTP) Generate(counter uint64, secret []byte) (string, error) {
	hashFunc, err := getHash(AlgHmacSha1, secret)
	if err != nil {
		return "", err
	}

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	return generateOTP(hashFunc, msg, h.Digits())
}

func (h *HOTP) GetURI(accountName, issuer string, secret []byte, counter uint64) (string, error) {
	return getOTPURI("hotp", accountName, issuer, secret, AlgHmacSha1, h.Digits(), int64(counter))
}
