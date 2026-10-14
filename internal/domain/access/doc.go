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

// Package access is the domain core of the breakglass operator: the rules that
// decide who may receive which emergency access, for how long, and when a
// granted access is no longer trustworthy.
//
// It is the single source of truth for these rules. Admission webhooks,
// reconcilers, and the expiry guard apply them; they do not restate them.
//
// The package depends on the Go standard library only. It knows nothing about
// Kubernetes clients, API machinery, or controller-runtime; adapters translate
// API objects into the plain values defined here. This boundary is enforced by
// the architecture test and the depguard configuration (see
// docs/adr-002-clean-architecture.md).
package access
