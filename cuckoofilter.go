package cuckoo

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
)

// maxCuckooKickouts is the maximum number of times reinsert
// is attempted.
const maxCuckooKickouts = 500

// Filter is a probabilistic counter.
type Filter struct {
	buckets []bucket
	count   uint
	// Bit mask set to len(buckets) - 1. As len(buckets) is always a power of 2,
	// applying this mask mimics the operation x % len(buckets).
	bucketIndexMask uint
	lock            sync.RWMutex
}

// NewFilter returns a new cuckoofilter suitable for the given number of elements.
// When inserting more elements, insertion speed will drop significantly and insertions might fail altogether.
// A capacity of 1000000 is a normal default, which allocates
// about ~2MB on 64-bit machines.
func NewFilter(numElements uint) *Filter {
	numBuckets := getNextPow2(uint64(numElements / bucketSize))
	if float64(numElements)/float64(numBuckets*bucketSize) > 0.96 {
		numBuckets <<= 1
	}
	if numBuckets == 0 {
		numBuckets = 1
	}
	buckets := make([]bucket, numBuckets)
	return &Filter{
		buckets:         buckets,
		count:           0,
		bucketIndexMask: uint(len(buckets) - 1),
		lock:            sync.RWMutex{},
	}
}

// Lookup returns true if data is in the filter.
func (cf *Filter) Lookup(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)

	cf.lock.RLock()
	if b := cf.buckets[i1]; b.contains(fp) {
		cf.lock.RUnlock()
		return true
	}
	cf.lock.RUnlock()

	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)

	cf.lock.RLock()
	defer cf.lock.RUnlock()

	b := cf.buckets[i2]
	return b.contains(fp)
}

// Reset removes all items from the filter, setting count to 0.
func (cf *Filter) Reset() {
	cf.lock.Lock()
	defer cf.lock.Unlock()

	for i := range cf.buckets {
		cf.buckets[i].reset()
	}
	cf.count = 0
}

// Insert data into the filter. Returns false if insertion failed. In the resulting state, the filter
// * Might return false negatives
// * Deletes are not guaranteed to work
// To increase success rate of inserts, create a larger filter.
func (cf *Filter) Insert(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	if cf.insert(fp, i1) {
		return true
	}
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	if cf.insert(fp, i2) {
		return true
	}
	return cf.reinsert(fp, randi(i1, i2))
}

func (cf *Filter) insert(fp fingerprint, i uint) bool {
	cf.lock.Lock()
	defer cf.lock.Unlock()

	if cf.buckets[i].insert(fp) {
		cf.count++
		return true
	}
	return false
}

func (cf *Filter) insertLockFree(fp fingerprint, i uint) bool {
	if cf.buckets[i].insert(fp) {
		cf.count++
		return true
	}
	return false
}

func (cf *Filter) reinsert(fp fingerprint, i uint) bool {
	cf.lock.Lock()
	defer cf.lock.Unlock()

	for k := 0; k < maxCuckooKickouts; k++ {
		j := rand.Intn(bucketSize)
		// Swap fingerprint with bucket entry.
		cf.buckets[i][j], fp = fp, cf.buckets[i][j]

		// Move kicked out fingerprint to alternate location.
		i = getAltIndex(fp, i, cf.bucketIndexMask)
		if cf.insertLockFree(fp, i) {
			return true
		}
	}
	return false
}

// Delete data from the filter. Returns true if the data was found and deleted.
func (cf *Filter) Delete(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	return cf.delete(fp, i1) || cf.delete(fp, i2)
}

func (cf *Filter) delete(fp fingerprint, i uint) bool {
	cf.lock.Lock()
	defer cf.lock.Unlock()

	if cf.buckets[i].delete(fp) {
		cf.count--
		return true
	}
	return false
}

// Count returns the number of items in the filter.
func (cf *Filter) Count() uint {
	cf.lock.RLock()
	defer cf.lock.RUnlock()

	return cf.count
}

// LoadFactor returns the fraction slots that are occupied.
func (cf *Filter) LoadFactor() float64 {
	cf.lock.RLock()
	defer cf.lock.RUnlock()

	return float64(cf.count) / float64(len(cf.buckets)*bucketSize)
}

// Encode returns a byte slice representing a Cuckoofilter.
func (cf *Filter) Encode() []byte {
	bytes := make([]byte, 0, len(cf.buckets)*bucketSize*fingerprintSizeBits/8)
	for _, b := range cf.buckets {
		for _, f := range b {
			next := make([]byte, 2)
			binary.LittleEndian.PutUint16(next, uint16(f))
			bytes = append(bytes, next...)
		}
	}
	return bytes
}

// Decode returns a Cuckoofilter from a byte slice created using Encode.
func Decode(bytes []byte) (*Filter, error) {
	var count uint
	if len(bytes)%bucketSize != 0 {
		return nil, fmt.Errorf("expected bytes to be multiple of %d, got %d", bucketSize, len(bytes))
	}
	buckets := make([]bucket, len(bytes)/4*8/fingerprintSizeBits)
	for i, b := range buckets {
		for j := range b {
			var next []byte
			next, bytes = bytes[0:2], bytes[2:]

			if fp := fingerprint(binary.LittleEndian.Uint16(next)); fp != 0 {
				buckets[i][j] = fp
				count++
			}
		}
	}
	return &Filter{
		buckets:         buckets,
		count:           count,
		bucketIndexMask: uint(len(buckets) - 1),
	}, nil
}
