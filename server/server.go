package server

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"plugin"
	"strings"

	storagePlugin "github.com/grexie/vault/storage"
)

type QuietFlagSet struct {
	*flag.FlagSet
}

func (f *QuietFlagSet) failf(format string, a ...interface{}) error {
	return nil
}

var addr *string
var driverPath *string
var storage storagePlugin.Driver

func resolveDriverPath() (string, error) {
	p := *driverPath

	if !strings.HasSuffix(p, ".so") {
		p = fmt.Sprintf("%v.so", p)
	}

	if _, err := os.Stat(p); err != nil {
		return "", err
	} else {
		return p, nil
	}
}

func loadStorageDriver() error {
	if d, err := resolveDriverPath(); err != nil {
		return err
	} else if p, err := plugin.Open(d); err != nil {
		return err
	} else if d, err := p.Lookup("Driver"); err != nil {
		return err
	} else if driver, ok := d.(storagePlugin.Driver); !ok {
		return fmt.Errorf("%v does not implement storage.Driver", driverPath)
	} else {
		flagSet := newFlagSet(flag.ExitOnError)

		if err := driver.CreateFlags(flagSet); err != nil {
			return err
		} else if err := flagSet.Parse(os.Args[2:]); err != nil {
			return err
		} else if err := driver.Initialize(); err != nil {
			return err
		} else {
			storage = driver
			return nil
		}
	}
}

func newFlagSet(errorHandling flag.ErrorHandling) *flag.FlagSet {
	flagSet := flag.NewFlagSet("server", errorHandling)
	addr = flagSet.String("addr", ":8080", "http service address")
	driverPath = flagSet.String("driver", "mdbx", "storage driver")

	return flagSet
}

func NewFlagSet() *flag.FlagSet {
	flagSet := newFlagSet(flag.ContinueOnError)
	buf := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(buf)
	return flagSet
}

func Run() error {
	if err := loadStorageDriver(); err != nil {
		return err
	}

	http.HandleFunc("/", websocketHandler)
	return http.ListenAndServe(*addr, nil)
}
