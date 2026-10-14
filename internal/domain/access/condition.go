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

package access

import "time"

// ConditionStatus is the tri-state value of a condition.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// Condition is one observation about an object, following the Kubernetes
// condition conventions.
type Condition struct {
	Type               string
	Status             ConditionStatus
	ObservedGeneration int64
	LastTransitionTime time.Time
	Reason             string
	Message            string
}

// SetCondition adds or updates the condition of the same type. The transition
// time changes only when the status changes, as in the Kubernetes API
// conventions.
func SetCondition(conditions *[]Condition, condition Condition, now time.Time) {
	for i := range *conditions {
		existing := &(*conditions)[i]
		if existing.Type != condition.Type {
			continue
		}
		if existing.Status != condition.Status {
			existing.Status = condition.Status
			existing.LastTransitionTime = condition.LastTransitionTime
			if existing.LastTransitionTime.IsZero() {
				existing.LastTransitionTime = now
			}
		}
		existing.Reason = condition.Reason
		existing.Message = condition.Message
		existing.ObservedGeneration = condition.ObservedGeneration
		return
	}
	if condition.LastTransitionTime.IsZero() {
		condition.LastTransitionTime = now
	}
	*conditions = append(*conditions, condition)
}

// FindCondition returns the condition of the given type, or nil.
func FindCondition(conditions []Condition, conditionType string) *Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
