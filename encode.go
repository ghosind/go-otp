package otp

// encode encodes the given number into a zero-padded string of the specified length.
func encode(num uint64, length int) string {
	res := make([]byte, length)

	for i := length - 1; i >= 0; i-- {
		res[i] = byte('0' + (num % 10))
		num /= 10
	}

	return string(res)
}
