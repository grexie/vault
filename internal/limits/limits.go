// Package limits defines the lease bounds shared by clients and signing workers.
package limits

import "time"

const MaxLeaseDuration = 48 * time.Hour
