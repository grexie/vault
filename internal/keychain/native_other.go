//go:build !darwin || !cgo

package keychain

import "errors"

type unavailable struct{}

func newNative() Native { return unavailable{} }
func (unavailable) ChromePassword() ([]byte, error) {
	return nil, errors.New("native Keychain import requires a macOS build with cgo; use --csv")
}
func (unavailable) InternetPassword(string, string) ([]byte, error) {
	return nil, errors.New("native Keychain import requires a macOS build with cgo; use --csv")
}
