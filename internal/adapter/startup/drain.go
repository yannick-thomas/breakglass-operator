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

package startup

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// DefaultShutdownDelay is how long a terminating admission pod keeps serving.
// Removing a pod from its Service's endpoints and reprogramming every node's
// proxy takes a few seconds; a webhook that stops at once leaves the API
// server calling a dead address until its 5s timeout, and admission fails
// closed.
const DefaultShutdownDelay = 15 * time.Second

// Drain delays shutdown after the first termination signal: readiness fails
// at once, while the server keeps answering until the delay has passed. A
// second signal exits immediately.
type Drain struct {
	draining atomic.Bool
}

// errDraining is the readiness failure reported while draining.
var errDraining = errors.New("shutting down")

// ReadyCheck fails once draining has started. It matches the
// controller-runtime healthz.Checker signature.
func (d *Drain) ReadyCheck(*http.Request) error {
	if d.draining.Load() {
		return errDraining
	}
	return nil
}

// Context returns a context that is cancelled delay after the first value on
// signals. On a second value, exit is called. The returned context is the
// manager's run context.
func (d *Drain) Context(signals <-chan os.Signal, delay time.Duration, exit func()) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signals
		d.draining.Store(true)
		select {
		case <-time.After(delay):
			cancel()
		case <-signals:
			cancel()
			exit()
		}
	}()
	return ctx
}
