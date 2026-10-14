/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package port defines the error outcomes that use cases distinguish when they
// talk to a gateway. Adapters classify their infrastructure errors with Mark,
// so use cases can decide on outcomes without importing any client library.
package port

import "errors"

var (
	// ErrNotFound means the object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists means an object with that name already exists.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict means the object changed since it was read, or a
	// precondition such as its UID no longer holds.
	ErrConflict = errors.New("conflict")
	// ErrForbidden means the caller lacks permission for the operation.
	ErrForbidden = errors.New("forbidden")
)

// Mark classifies err as kind. The result keeps err's message and still
// matches err itself with errors.Is and errors.As.
func Mark(kind, err error) error {
	if err == nil {
		return nil
	}
	return &marked{kind: kind, err: err}
}

type marked struct {
	kind error
	err  error
}

func (m *marked) Error() string   { return m.err.Error() }
func (m *marked) Unwrap() []error { return []error{m.kind, m.err} }
