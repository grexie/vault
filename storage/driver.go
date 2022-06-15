package storage

import "flag"

type Cursor interface{}

type Item struct {
	Key   string
	Value string
}

type Page struct {
	Items []Item
	Next  Cursor
}

type Driver interface {
	CreateFlags(flagSet *flag.FlagSet) error
	Initialize() error
	List(domain string, cursor Cursor) (*Page, error)
	Get(domain string, key string) (*Item, error)
	Set(domain string, key string, value string) error
	Remove(domain string, key string) error
	Flush(domain string) error
}
