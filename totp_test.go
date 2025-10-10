package otp_test

import (
	"testing"
	"time"

	"github.com/ghosind/go-assert"
	"github.com/ghosind/go-otp"
)

func TestTOTPGenerate(t *testing.T) {
	a := assert.New(t)
	totps := map[otp.Algorithm]*otp.TOTP{
		otp.HmacSha1:   otp.NewTOTP(otp.WithAlgorithm(otp.HmacSha1), otp.WithDigits(8)),
		otp.HmacSha256: otp.NewTOTP(otp.WithAlgorithm(otp.HmacSha256), otp.WithDigits(8)),
		otp.HmacSha512: otp.NewTOTP(otp.WithAlgorithm(otp.HmacSha512), otp.WithDigits(8)),
	}
	secrets := map[otp.Algorithm][]byte{
		otp.HmacSha1:   []byte("12345678901234567890"),
		otp.HmacSha256: []byte("12345678901234567890123456789012"),
		otp.HmacSha512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}

	// Test vectors from RFC 6238
	// https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
	vectors := []struct {
		algo   otp.Algorithm
		tm     int64
		expect string
	}{
		// 1970-01-01 00:00:59 UTC
		{otp.HmacSha1, 59, "94287082"},
		{otp.HmacSha256, 59, "46119246"},
		{otp.HmacSha512, 59, "90693936"},

		// 2005-03-18 01:58:29 UTC
		{otp.HmacSha1, 1111111109, "07081804"},
		{otp.HmacSha256, 1111111109, "68084774"},
		{otp.HmacSha512, 1111111109, "25091201"},

		// 2005-03-18 01:58:31 UTC
		{otp.HmacSha1, 1111111111, "14050471"},
		{otp.HmacSha256, 1111111111, "67062674"},
		{otp.HmacSha512, 1111111111, "99943326"},

		// 2009-02-13 23:31:30 UTC
		{otp.HmacSha1, 1234567890, "89005924"},
		{otp.HmacSha256, 1234567890, "91819424"},
		{otp.HmacSha512, 1234567890, "93441116"},

		// 2033-05-18 03:33:20 UTC
		{otp.HmacSha1, 2000000000, "69279037"},
		{otp.HmacSha256, 2000000000, "90698825"},
		{otp.HmacSha512, 2000000000, "38618901"},

		// 2603-05-18 03:33:20 UTC
		{otp.HmacSha1, 20000000000, "65353130"},
		{otp.HmacSha256, 20000000000, "77737706"},
		{otp.HmacSha512, 20000000000, "47863826"},
	}

	for _, v := range vectors {
		secret := secrets[v.algo]
		tm := time.Unix(v.tm, 0)
		result, err := totps[v.algo].GenerateWithTime(tm, secret)
		a.NilNow(err)
		a.EqualNow(v.expect, result)
	}
}
