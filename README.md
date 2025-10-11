# go-otp

![test](https://github.com/ghosind/go-otp/workflows/test/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ghosind/go-otp)](https://goreportcard.com/report/github.com/ghosind/go-otp)
[![codecov](https://codecov.io/gh/ghosind/go-otp/branch/main/graph/badge.svg)](https://codecov.io/gh/ghosind/go-otp)
![Version Badge](https://img.shields.io/github/v/release/ghosind/go-otp)
![License Badge](https://img.shields.io/github/license/ghosind/go-otp)
[![Go Reference](https://pkg.go.dev/badge/github.com/ghosind/go-otp.svg)](https://pkg.go.dev/github.com/ghosind/go-otp)

go-otp is a Go library for generating OTP (One-Time Password) codes. It currently supports TOTP (Time-based One-Time Password, RFC 6238) and is suitable for two-factor authentication, dynamic password, and other security scenarios.

- TOTP: Time-based One-Time Password ([RFC 6238](https://tools.ietf.org/html/rfc6238))
- HOTP: HMAC-based One-Time Password ([RFC 4226](https://tools.ietf.org/html/rfc4226)) (Not implemented yet)

## Features

- Supports multiple hash algorithms: SHA1, SHA256, SHA512
- Customizable code length and period
- Compatible with popular TOTP apps (e.g., Google Authenticator)
- Simple and easy-to-use API

## Installation

```bash
go get github.com/ghosind/go-otp
```

## Quick Start

```go
package main

import (
	"fmt"
	"time"
	"github.com/ghosind/go-otp"
)

func main() {
	secret := []byte("your-secret-key")
	totp := otp.NewTOTP(
		otp.WithAlgorithm(otp.AlgHmacSha1),
		otp.WithDigits(6),
		otp.WithPeriod(30),
	)
	code, err := totp.Generate(secret)
	if err != nil {
		panic(err)
	}
	fmt.Println("TOTP Code:", code)

	// Generate code for a specific time
	customTime := time.Now()
	code, _ = totp.GenerateWithTime(customTime, secret)
	fmt.Println("Custom Time TOTP:", code)
}
```

## API Reference

- `NewTOTP(options...)` creates a TOTP instance
- `Generate(secret []byte)` generates a code for the current time
- `GenerateWithTime(t time.Time, secret []byte)` generates a code for a specific time

See more usage in the [GoDoc](https://pkg.go.dev/github.com/ghosind/go-otp).

## Testing

The project includes RFC 6238 standard test vectors to ensure algorithm correctness.

Run tests:

```bash
go test ./...
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
