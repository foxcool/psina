package store

import "time"

// RefreshSweepGrace is how long after its last member expires a refresh
// token family is kept before a sweep may delete it.
//
// A refresh rotates a member while it is still live and saves the successor
// a moment later, possibly after that member has expired; deleting the
// family in between would refuse the successor (its root is gone) and fail
// a refresh that already won rotation. The grace must exceed any request's
// duration plus clock skew between replicas; an hour is far beyond both
// and costs nothing next to the refresh token TTL.
const RefreshSweepGrace = time.Hour
