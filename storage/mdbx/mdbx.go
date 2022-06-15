package main

import (
	"flag"
	"log"
	"os"
	"path"

	"github.com/grexie/vault/storage"
)

type MdbxDriver struct {
	datadir *string
}

func (d *MdbxDriver) CreateFlags(flagSet *flag.FlagSet) error {
	if datadir, err := os.UserConfigDir(); err != nil {
		return err
	} else {
		d.datadir = flagSet.String("datadir", path.Join(datadir, "grexie", "vault"), "the directory in which to store data")
	}

	return nil
}

func (d *MdbxDriver) Initialize() error {
	log.Println("mdbx:initialize")
	return nil
}

func (d *MdbxDriver) List(domain string, cursor storage.Cursor) (*storage.Page, error) {
	log.Println("mdbx:list", domain, cursor)
	return nil, nil
}

func (d *MdbxDriver) Get(domain string, key string) (*storage.Item, error) {
	log.Println("mdbx:get", domain, key)
	return nil, nil
}

func (d *MdbxDriver) Set(domain string, key string, value string) error {
	log.Println("mdbx:set", domain, key, value)
	return nil
}

func (d *MdbxDriver) Remove(domain string, key string) error {
	log.Println("mdbx:remove", domain, key)
	return nil
}

func (d *MdbxDriver) Flush(domain string) error {
	log.Println("mdbx:flush", domain)
	return nil
}

var Driver = MdbxDriver{}
