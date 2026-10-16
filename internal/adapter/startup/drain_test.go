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
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDrainKeepsServingUntilTheDelayHasPassed(t *testing.T) {
	var drain Drain
	signals := make(chan os.Signal, 2)
	ctx := drain.Context(signals, 50*time.Millisecond, func() { t.Error("exit called on a single signal") })

	if err := drain.ReadyCheck(nil); err != nil {
		t.Fatalf("ReadyCheck() before a signal = %v, want ready", err)
	}
	signals <- syscall.SIGTERM
	deadline := time.Now().Add(time.Second)
	for drain.ReadyCheck(nil) == nil {
		if time.Now().After(deadline) {
			t.Fatal("readiness did not fail after the termination signal")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-ctx.Done():
		t.Fatal("context cancelled before the shutdown delay passed")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled after the shutdown delay")
	}
}

func TestDrainExitsOnASecondSignal(t *testing.T) {
	var drain Drain
	signals := make(chan os.Signal, 2)
	exited := make(chan struct{})
	ctx := drain.Context(signals, time.Hour, func() { close(exited) })

	signals <- syscall.SIGTERM
	signals <- syscall.SIGINT
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("a second signal must exit immediately")
	}
	if ctx.Err() == nil {
		t.Fatal("context must be cancelled on a second signal")
	}
}
