# Application Gateways and Credentials (Optional)

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

CONNECT carries an opaque byte stream, and destination policy is the only
decision the wire profile makes. An operator who needs application-level
visibility, or who wants to keep service credentials out of the workload,
adds an application gateway. This document states the requirements on such a
gateway and where credentials can be held. Gateways are outside the wire
profile and are not a conformance role in this version.

## 1. TLS Inspection and Verification Models

TLS inspection is optional. A gateway can either read the visible TLS
handshake without decrypting it (Section 1.1) or terminate TLS (Section 1.2).

### 1.1 Passive TLS Handshake Peeking (No Decryption)

CONNECT normally preserves end-to-end encryption. A tunnel-aware
implementation can read a visible TLS ClientHello and compare its SNI with
the requested destination. The comparison is a consistency check. It does not
authenticate the destination, inspect the payload, or rule out domain
fronting. Encrypted ClientHello and non-TLS protocols limit what the check
can see. A TLS inspector on an ordinary listener does not by itself inspect
TLS nested inside CONNECT streams.

### 1.2 Full TLS Termination (Layer 7 Inspection)

An operator who requires Layer 7 visibility, for example for credential
injection, compliance auditing, data loss prevention, or structured agent
instructions, terminates TLS at the gateway. The arrangement has four parts.

1. The host mounts a trusted root CA certificate into the sandbox and names
   its path in an environment variable:

   ```bash
   AGENT_CA_CERT=/var/run/agent-ca.pem
   ```

2. The sandbox environment SHOULD map `AGENT_CA_CERT` to the environment
   variables that common runtimes read:
   - `REQUESTS_CA_BUNDLE=$AGENT_CA_CERT`
   - `SSL_CERT_FILE=$AGENT_CA_CERT`
   - `NODE_EXTRA_CA_CERTS=$AGENT_CA_CERT`
3. The application gateway can then attach host-held credentials to
   authorized requests, inspect or redact content, and return
   application-level errors or rate limits.
4. An application that does not trust the gateway's CA fails certificate
   validation for inspected destinations. Uninspected tunnels and destination
   policy are unaffected.

The gateway needs protocol-specific support for each HTTP version, for
streaming, and for credential use. Certificate pinning can prevent TLS
inspection. Keeping a key outside the sandbox does not by itself prevent
misuse of the API behind it, so permitted operations and usage also need
limits. These functions are separate from CONNECT tunneling. The
requirements of [wire.md Section 9](wire.md#9-untrusted-tunnel-content) on
inspecting gateways apply.

### 1.3 The Gateway's Certificate Authority

A sandbox that trusts the gateway's CA accepts every certificate the CA
signs. Whoever holds the CA's key can therefore impersonate any server to the
sandbox, and to any other client that trusts the CA. The following limits
narrow what the CA can sign:

- The CA certificate SHOULD carry a critical name constraints extension
  ([RFC 5280 Section 4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10))
  that permits only the DNS names of the inspected destinations and excludes
  all IPv4 and IPv6 addresses. A permitted name also covers its subdomains.
  A client that checks name constraints then rejects a certificate for any
  other name, even one signed with the CA's key.
- The CA certificate SHOULD have a path length constraint of zero, so that
  the CA cannot issue intermediate CAs.
- Each leaf certificate SHOULD name only the destination it serves.

The CA's key MUST NOT be readable from any sandbox. A CA SHOULD serve one
deployment, and its certificate SHOULD NOT be added to trust stores outside
the sandboxes that use the gateway. A gateway SHOULD keep the key in memory
and create a new CA each time it starts, so that a copied key stops being
useful once the sandboxes that trust it end. When the inspected destinations
change, the controller gives the sandbox the new CA certificate at the start
of its next generation ([lifecycle.md](lifecycle.md)).

## 2. Credential Placement and Tenant Isolation

| Component | Permitted authority |
| --- | --- |
| Workload and compatibility adapter | Its assigned data channels; no reusable provider credentials |
| Optional FD broker | Authenticated registration and descriptor placement; no provider-key inventory |
| Boundary proxy | Policy for assigned channels and narrowly scoped transport identity where required |
| Application gateway | Credentials for its assigned tenant and permitted upstream operations |
| Controller and issuer | Provisioning and issuance authority, inaccessible from workload data channels |

A credential gateway MUST select credentials from the authenticated channel
identity and the authorized service, and never from guest headers or a
supplied credential identifier alone. Credentials MUST be scoped to a tenant,
an audience, a service, and a set of permitted operations. Short-lived
credentials are preferred, and request, usage, and spending limits are
enforced where applicable. A generic CONNECT boundary MUST NOT inject origin
credentials into an opaque byte stream.

An application gateway MUST remove the guest credentials it replaces and
attach its own credentials only after authorization and upstream
authentication. It MUST prevent credentials from being forwarded to
unauthorized redirects, alternate origins, or upgraded protocols, including
on later requests over a reused connection.

Before it attaches a credential to a request, the gateway MUST check that the
request names the destination that the CONNECT request named and the
boundary authorized. The check covers the TLS server name when the client
sends one, and the `Host` field or `:authority` pseudo-header of every
request on the connection. Servers behind a shared CDN or front end choose
the origin by the `Host` field, so a request on an authorized tunnel that
names another host can carry the credential to another origin. The gateway
MUST NOT attach a credential to such a request, and SHOULD refuse it with
421 (Misdirected Request). It SHOULD also refuse request targets that are
not in origin form, because some servers choose the origin by an
absolute-form target.

Bearer tokens, private keys, and sensitive request bodies MUST NOT appear in
logs, error responses, shared files, or workload environments.

Separate sockets provide attribution and endpoint access control. They do not
isolate process memory, so a compromised process that holds keys for several
tenants can expose all of them. A deployment that requires isolation between
mutually untrusted tenants SHOULD use separate credential-bearing workers or
an equivalent isolation boundary. A signing service or a non-exportable key
limits key extraction, but a compromised caller that is authorized to use the
key can still misuse it, so the key service needs its own checks on operation
and audience.
