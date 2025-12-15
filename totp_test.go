package otp_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/ghosind/go-assert"
	"github.com/ghosind/go-otp"
)

func TestTOTP(t *testing.T) {
	a := assert.New(t)
	totps := map[otp.Algorithm]*otp.TOTP{
		otp.AlgHmacSha1:   otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha1), otp.WithDigits(8)),
		otp.AlgHmacSha256: otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha256), otp.WithDigits(8)),
		otp.AlgHmacSha512: otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha512), otp.WithDigits(8)),
	}
	secrets := map[otp.Algorithm][]byte{
		otp.AlgHmacSha1:   []byte("12345678901234567890"),
		otp.AlgHmacSha256: []byte("12345678901234567890123456789012"),
		otp.AlgHmacSha512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}

	// Test vectors from RFC 6238
	// https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
	vectors := []struct {
		algo   otp.Algorithm
		tm     int64
		expect string
	}{
		// 1970-01-01 00:00:59 UTC
		{otp.AlgHmacSha1, 59, "94287082"},
		{otp.AlgHmacSha256, 59, "46119246"},
		{otp.AlgHmacSha512, 59, "90693936"},

		// 2005-03-18 01:58:29 UTC
		{otp.AlgHmacSha1, 1111111109, "07081804"},
		{otp.AlgHmacSha256, 1111111109, "68084774"},
		{otp.AlgHmacSha512, 1111111109, "25091201"},

		// 2005-03-18 01:58:31 UTC
		{otp.AlgHmacSha1, 1111111111, "14050471"},
		{otp.AlgHmacSha256, 1111111111, "67062674"},
		{otp.AlgHmacSha512, 1111111111, "99943326"},

		// 2009-02-13 23:31:30 UTC
		{otp.AlgHmacSha1, 1234567890, "89005924"},
		{otp.AlgHmacSha256, 1234567890, "91819424"},
		{otp.AlgHmacSha512, 1234567890, "93441116"},

		// 2033-05-18 03:33:20 UTC
		{otp.AlgHmacSha1, 2000000000, "69279037"},
		{otp.AlgHmacSha256, 2000000000, "90698825"},
		{otp.AlgHmacSha512, 2000000000, "38618901"},

		// 2603-05-18 03:33:20 UTC
		{otp.AlgHmacSha1, 20000000000, "65353130"},
		{otp.AlgHmacSha256, 20000000000, "77737706"},
		{otp.AlgHmacSha512, 20000000000, "47863826"},
	}

	for _, v := range vectors {
		secret := secrets[v.algo]
		tm := time.Unix(v.tm, 0)
		result, err := totps[v.algo].GenerateWithTime(tm, secret)
		a.NilNow(err)
		a.EqualNow(v.expect, result)
	}
}

func TestTOTP_Algorithm(t *testing.T) {
	a := assert.New(t)

	const invalidAlgorithm otp.Algorithm = 100

	totp := otp.NewTOTP()
	a.EqualNow(otp.AlgHmacSha1, totp.Algorithm())

	totp = otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha256))
	a.EqualNow(otp.AlgHmacSha256, totp.Algorithm())

	totp = otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha512))
	a.EqualNow(otp.AlgHmacSha512, totp.Algorithm())

	totp = otp.NewTOTP(otp.WithAlgorithm(otp.AlgDefault))
	a.EqualNow(otp.AlgHmacSha1, totp.Algorithm())

	totp = otp.NewTOTP(otp.WithAlgorithm(invalidAlgorithm))
	a.EqualNow(otp.AlgHmacSha1, totp.Algorithm())
}

func TestTOTP_Digits(t *testing.T) {
	a := assert.New(t)

	totp := otp.NewTOTP()
	a.EqualNow(6, totp.Digits())

	totp = otp.NewTOTP(otp.WithDigits(0))
	a.EqualNow(6, totp.Digits())

	totp = otp.NewTOTP(otp.WithDigits(-1))
	a.EqualNow(6, totp.Digits())

	totp = otp.NewTOTP(otp.WithDigits(1))
	a.EqualNow(1, totp.Digits())

	totp = otp.NewTOTP(otp.WithDigits(8))
	a.EqualNow(8, totp.Digits())

	totp = otp.NewTOTP(otp.WithDigits(9))
	a.EqualNow(6, totp.Digits())
}

func TestTOTP_Period(t *testing.T) {
	a := assert.New(t)

	totp := otp.NewTOTP()
	a.EqualNow(int64(30), totp.Period())

	totp = otp.NewTOTP(otp.WithPeriod(0))
	a.EqualNow(int64(30), totp.Period())

	totp = otp.NewTOTP(otp.WithPeriod(-1))
	a.EqualNow(int64(30), totp.Period())

	totp = otp.NewTOTP(otp.WithPeriod(10))
	a.EqualNow(int64(10), totp.Period())

	totp = otp.NewTOTP(otp.WithPeriod(60))
	a.EqualNow(int64(60), totp.Period())
}

func TestTOTP_Generate(t *testing.T) {
	a := assert.New(t)
	totp := otp.NewTOTP(otp.WithDigits(8))
	secret := []byte("12345678901234567890")
	result, err := totp.Generate(secret)
	a.NilNow(err)
	a.EqualNow(len(result), 8)
}

func TestTOTP_GenerateWithTime(t *testing.T) {
	a := assert.New(t)
	totp := otp.NewTOTP(otp.WithDigits(8))
	secret := []byte("12345678901234567890")
	result, err := totp.GenerateWithTime(time.Unix(59, 0), secret)
	a.NilNow(err)
	a.EqualNow(result, "94287082")
}

func TestTOTP_GetURI(t *testing.T) {
	a := assert.New(t)

	topt := otp.NewTOTP()
	secret := []byte("12345678901234567890")
	expectedURI := "otpauth://totp/ExampleIssuer:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ExampleIssuer"

	uri, err := topt.GetURI("user@example.com", "ExampleIssuer", secret)
	a.NilNow(err)
	URLsEqual(a, expectedURI, uri)

	totp := otp.NewTOTP(otp.WithAlgorithm(otp.AlgHmacSha256), otp.WithDigits(8), otp.WithPeriod(60))
	expectedURI = "otpauth://totp/ExampleIssuer:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ExampleIssuer&algorithm=SHA256&digits=8&period=60"

	uri, err = totp.GetURI("user@example.com", "ExampleIssuer", secret)
	a.NilNow(err)
	URLsEqual(a, expectedURI, uri)
}

func ExampleTOTP() {
	totp := otp.NewTOTP()
	secret := []byte("12345678901234567890")
	code, _ := totp.GenerateWithTime(time.Date(2006, time.January, 2, 15, 4, 5, 0, time.UTC), secret)
	fmt.Println(code)
	// Output:
	// 413931
}
