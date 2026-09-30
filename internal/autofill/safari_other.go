//go:build !darwin

package autofill

import (
	"context"
	"errors"
)

func OpenSafari(string) (Browser, error) { return nil, errors.New("Safari automation requires macOS") }
func SafariTargets(context.Context) ([]Target, error) {
	return nil, errors.New("Safari automation requires macOS")
}
