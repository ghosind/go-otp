package otp_test

import (
	"fmt"
	"testing"

	"github.com/ghosind/go-assert"
	"github.com/ghosind/go-otp"
)

func TestHOTP(t *testing.T) {
	a := assert.New(t)
	secret := []byte("12345678901234567890")
	expected := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	hotp := otp.NewHOTP()
	for i, exp := range expected {
		code, err := hotp.Generate(uint64(i), secret)
		a.NilNow(err)
		a.EqualNow(exp, code)
	}
}

func TestHOTP_Digits(t *testing.T) {
	a := assert.New(t)

	hotp := otp.NewHOTP()
	a.EqualNow(6, hotp.Digits())

	hotp = otp.NewHOTP(otp.WithDigits(0))
	a.EqualNow(6, hotp.Digits())

	hotp = otp.NewHOTP(otp.WithDigits(-1))
	a.EqualNow(6, hotp.Digits())

	hotp = otp.NewHOTP(otp.WithDigits(1))
	a.EqualNow(1, hotp.Digits())

	hotp = otp.NewHOTP(otp.WithDigits(8))
	a.EqualNow(8, hotp.Digits())

	hotp = otp.NewHOTP(otp.WithDigits(9))
	a.EqualNow(6, hotp.Digits())
}

func TestHOTP_Generate(t *testing.T) {
	a := assert.New(t)
	hotp := otp.NewHOTP(otp.WithDigits(8))
	secret := []byte("12345678901234567890")
	code, err := hotp.Generate(0, secret)
	a.NilNow(err)
	a.EqualNow("84755224", code)
}

func ExampleHOTP() {
	hotp := otp.NewHOTP()
	secret := []byte("12345678901234567890")
	code, _ := hotp.Generate(0, secret)
	fmt.Println(code)
	// Output:
	// 755224
}
