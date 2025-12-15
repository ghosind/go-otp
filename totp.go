package otp

import (
	"encoding/binary"
	"time"
)

const (
	defaultTOTPDigits    = 6
	defaultTOTPPeriod    = 30
	defaultTOTPAlgorithm = AlgHmacSha1
)

// TOTP is Time-based One-Time Password algorithm implementation.
type TOTP struct {
	algorithm Algorithm
	digits    int
	period    int64
}

// NewTOTP creates a new TOTP instance with the given options.
func NewTOTP(opts ...Option) *TOTP {
	builder := new(otpBuilder)
	for _, opt := range opts {
		opt(builder)
	}

	return &TOTP{
		digits:    builder.digits,
		algorithm: builder.algorithm,
		period:    builder.period,
	}
}

// Algorithm returns the hashing algorithm used in TOTP. If not set, it defaults to HmacSha1.
func (t *TOTP) Algorithm() Algorithm {
	if t.algorithm < AlgHmacSha1 || t.algorithm > AlgHmacSha512 {
		return defaultTOTPAlgorithm
	}
	return t.algorithm
}

// Digits returns the number of digits in the generated TOTP. If not set, it defaults to 6.
func (t *TOTP) Digits() int {
	if t.digits <= 0 || t.digits > 8 {
		return defaultTOTPDigits
	}
	return t.digits
}

// Period returns the time period in seconds for which a TOTP is valid. If not set, it defaults to
// 30 seconds.
func (t *TOTP) Period() int64 {
	if t.period <= 0 {
		return defaultTOTPPeriod
	}
	return t.period
}

// Generate generates a TOTP using the current time and the provided secret key.
func (t *TOTP) Generate(secret []byte) (string, error) {
	return t.GenerateWithTime(time.Now(), secret)
}

// GenerateWithTime generates a TOTP for the given time and secret key.
func (t *TOTP) GenerateWithTime(tm time.Time, secret []byte) (string, error) {
	period := t.Period()
	counter := uint64(tm.Unix() / period)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	return t.generate(msg, secret)
}

// generate generates a TOTP based on the provided message and secret key.
func (t *TOTP) generate(msg, secret []byte) (string, error) {
	hashFunc, err := getHash(t.Algorithm(), secret)
	if err != nil {
		return "", err
	}

	return generateOTP(hashFunc, msg, t.Digits())
}

func (t *TOTP) GetURI(accountName, issuer string, secret []byte) (string, error) {
	return getOTPURI("totp", accountName, issuer, secret, t.Algorithm(), t.Digits(), t.Period())
}
