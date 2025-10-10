package otp

// otpBuilder is a builder for OTP configurations.
type otpBuilder struct {
	digits    int
	algorithm Algorithm
	period    int64
}

// Option represents a configuration option for OTPs.
type Option func(*otpBuilder)

// WithDigits sets the number of digits for the OTP.
func WithDigits(digits int) Option {
	return func(b *otpBuilder) {
		b.digits = digits
	}
}

// WithAlgorithm sets the hashing algorithm for the OTP.
func WithAlgorithm(algorithm Algorithm) Option {
	return func(b *otpBuilder) {
		b.algorithm = algorithm
	}
}

// WithPeriod sets the time period in seconds for which a TOTP is valid. It configures the TOTP
// only.
func WithPeriod(period int64) Option {
	return func(b *otpBuilder) {
		b.period = period
	}
}
