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

package hosttun

import "testing"

func TestParseIsolationMode(t *testing.T) {
	tests := []struct {
		raw     string
		want    IsolationMode
		wantErr bool
	}{
		{raw: "", want: IsolationShared},
		{raw: "shared", want: IsolationShared},
		{raw: "per-pod", want: IsolationPerPod},
		{raw: "invalid", wantErr: true},
		{raw: "SHARED", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseIsolationMode(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseIsolationMode(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseIsolationMode(%q) unexpected error: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseIsolationMode(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
