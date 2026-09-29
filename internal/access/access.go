// Package access defines the immutable operations approved for a lease.
package access

import "errors"

const (
	SSH  = "ssh"
	Age  = "age"
	Both = "ssh,age"
)

func Normalize(value string) (string, error) {
	switch value {
	case "", SSH:
		return SSH, nil
	case Age:
		return Age, nil
	case Both, "age,ssh":
		return Both, nil
	default:
		return "", errors.New("access must be ssh, age, or ssh,age")
	}
}

func AllowsSSH(value string) bool { return value == "" || value == SSH || value == Both }
func AllowsAge(value string) bool { return value == Age || value == Both }
