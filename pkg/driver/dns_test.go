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

package driver

import (
	"os"
	"testing"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/params"
)

func TestWriteHostTunResolvConf(t *testing.T) {
	// 1. Default Synthetic mode strips search domains and ndots:5.
	p1, err := writeHostTunResolvConf(t.TempDir(), "agents", params.Defaults())
	if err != nil {
		t.Fatalf("writeHostTunResolvConf synthetic: %v", err)
	}
	got1, _ := os.ReadFile(p1)
	if want := "nameserver 198.19.255.253\n"; string(got1) != want {
		t.Fatalf("synthetic resolv.conf = %q, want %q", got1, want)
	}

	// 2. DoH mode preserves Kubernetes search domains and ndots:5 by default.
	dohParams := params.Defaults()
	dohParams.DNS = &apis.DNSConfig{Mode: apis.DNSModeDoH}
	p2, err := writeHostTunResolvConf(t.TempDir(), "team-a", dohParams)
	if err != nil {
		t.Fatalf("writeHostTunResolvConf DoH: %v", err)
	}
	got2, _ := os.ReadFile(p2)
	want2 := "nameserver 198.19.255.253\nsearch team-a.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n"
	if string(got2) != want2 {
		t.Fatalf("DoH resolv.conf = %q, want %q", got2, want2)
	}

	// 3. DoH mode with custom clusterDomain and preserveSearchDomains=false.
	preserveFalse := false
	dohNoSearch := params.Defaults()
	dohNoSearch.DNS = &apis.DNSConfig{
		Mode:                  apis.DNSModeDoH,
		ClusterDomain:         "corp.internal",
		PreserveSearchDomains: &preserveFalse,
	}
	p3, err := writeHostTunResolvConf(t.TempDir(), "team-a", dohNoSearch)
	if err != nil {
		t.Fatalf("writeHostTunResolvConf DoH no search: %v", err)
	}
	got3, _ := os.ReadFile(p3)
	if want := "nameserver 198.19.255.253\n"; string(got3) != want {
		t.Fatalf("DoH preserveSearchDomains=false resolv.conf = %q, want %q", got3, want)
	}
}
