// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
	"k8s.io/apimachinery/pkg/types"
)

const checkpointSchemaVersion = 1

var (
	metaBucket       = []byte("meta")
	schemaVersionKey = []byte("schemaVersion")
	podConfigsBucket = []byte("pod_configs")
)

// BoltBackend persists checkpointed PodConfig payloads to a schema-versioned bbolt
// database on node-local memory-backed tmpfs.
type BoltBackend struct {
	db *bolt.DB
}

var _ Backend = &BoltBackend{}

// OpenBolt opens or initializes a bbolt checkpoint database at path.
func OpenBolt(path string) (*BoltBackend, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create checkpoint directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open checkpoint db %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(podConfigsBucket); err != nil {
			return err
		}
		meta, err := tx.CreateBucketIfNotExists(metaBucket)
		if err != nil {
			return err
		}
		version := 1
		if raw := meta.Get(schemaVersionKey); raw != nil {
			version, err = strconv.Atoi(string(raw))
			if err != nil || version < 1 {
				return fmt.Errorf("malformed checkpoint schema version %q", raw)
			}
		}
		if version > checkpointSchemaVersion {
			return fmt.Errorf("checkpoint schema version %d is newer than supported version %d", version, checkpointSchemaVersion)
		}
		return meta.Put(schemaVersionKey, []byte(strconv.Itoa(checkpointSchemaVersion)))
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize checkpoint db: %w", err)
	}
	return &BoltBackend{db: db}, nil
}

// Put writes serialized PodConfig bytes for podUID.
func (b *BoltBackend) Put(podUID types.UID, data []byte) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(podConfigsBucket)
		if root == nil {
			return berrors.ErrBucketNotFound
		}
		return root.Put([]byte(podUID), data)
	})
}

// LoadAll returns all persisted PodConfig payloads keyed by Pod UID.
func (b *BoltBackend) LoadAll() (map[types.UID][]byte, error) {
	out := make(map[types.UID][]byte)
	err := b.db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(podConfigsBucket)
		if root == nil {
			return nil
		}
		return root.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			out[types.UID(string(k))] = cp
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes podUID from the checkpoint database.
func (b *BoltBackend) Delete(podUID types.UID) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(podConfigsBucket)
		if root == nil {
			return nil
		}
		return root.Delete([]byte(podUID))
	})
}

// Close closes the bbolt database handle.
func (b *BoltBackend) Close() error {
	return b.db.Close()
}
