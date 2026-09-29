// Package limits defines the lease bounds shared by clients and signing workers.
package limits

import "time"

const MaxLeaseDuration = 48 * time.Hour

// Only the age header is sent to the worker, never the document payload.
const MaxAgeHeader = 64 * 1024

// Persistent approval windows are separate from individual job/SSH leases.
const MaxIdleDuration = 365 * 24 * time.Hour
