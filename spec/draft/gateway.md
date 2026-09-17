# Application Gateways and Credentials (Optional)

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

CONNECT carries an opaque byte stream; destination policy is all the wire
profile decides. Operators who need application-level visibility or who want
to keep service credentials out of the workload add an application gateway.
This document defines what such a gateway must do and where credentials may
live. Gateways are outside the wire profile and are not a conformance role in
this version.

## 1. TLS Inspection and Verification Models

CONNECT carries an opaque byte stream. TLS inspection is optional.

### 1.1 Passive TLS Handshake Peeking (No Decryption)

CONNECT normally preserves end-to-end encryption. A tunnel-aware implementation
may inspect a visible TLS ClientHello and compare SNI with the requested
destination. This is an additional consistency check, not destination
authentication, payload inspection, or proof against domain fronting. Encrypted
ClientHello and non-TLS protocols limit visibility. An ordinary listener TLS
inspector does not automatically inspect TLS nested inside CONNECT streams.

### 1.2 Full TLS Termination (Layer 7 Inspection)

When an operator requires Layer 7 visibility (e.g. for credential injection, compliance auditing, Data Loss Prevention, or structured agent instructions):

1. **Root CA Mounting:** The host mounts a trusted Root CA certificate into the sandbox:

   ```bash
   AGENT_CA_CERT=/var/run/agent-ca.pem
   ```

2. **Trust Store Coordination:** The sandbox environment SHOULD map `AGENT_CA_CERT` to standard runtime environment variables:
   - `REQUESTS_CA_BUNDLE=$AGENT_CA_CERT`
   - `SSL_CERT_FILE=$AGENT_CA_CERT`
   - `NODE_EXTRA_CA_CERTS=$AGENT_CA_CERT`
3. **Request processing:** The application gateway can attach host-held credentials to authorized requests, inspect or redact content, and return application-level errors or rate limits.
4. **Trust configuration:** Applications that do not trust the gateway's CA fail certificate validation for inspected destinations. Uninspected tunnels and destination policy are unaffected.

The gateway needs protocol-specific support for HTTP versions, streaming, and
credential use. Certificate pinning may prevent TLS inspection. Keeping a key
outside the sandbox does not prevent abuse of the API: permitted operations and
usage also need limits. These functions are separate from CONNECT tunneling.
The requirements of [wire.md Section 9](wire.md#9-untrusted-tunnel-content) on
inspecting gateways apply.

## 2. Credential Placement and Tenant Isolation

| Component | Permitted authority |
| --- | --- |
| Workload and compatibility adapter | Its assigned data channels; no reusable provider credentials |
| Optional FD broker | Authenticated registration and descriptor placement; no provider-key inventory |
| Boundary proxy | Policy for assigned channels and narrowly scoped transport identity where required |
| Application gateway | Credentials for its assigned tenant and permitted upstream operations |
| Controller and issuer | Provisioning and issuance authority, inaccessible from workload data channels |

Credential gateways MUST select credentials from the authenticated channel
identity and authorized service, never solely from guest headers or a supplied
credential identifier. Credentials MUST be scoped to tenant, audience, service,
and permitted operations. Prefer short-lived credentials and enforce request,
usage, and spending limits where applicable. A generic CONNECT boundary MUST
NOT inject origin credentials into an opaque byte stream.

An application gateway MUST remove guest credentials that it replaces and
attach its own credentials only after authorization and upstream authentication.
It MUST prevent credential forwarding to unauthorized redirects, alternate
origins, or upgraded protocols, including later requests on reused connections.
Bearer tokens, private keys, and sensitive request bodies MUST NOT appear in
logs, error responses, shared files, or workload environments.

Separate sockets provide attribution and endpoint access control, not process
memory isolation. A shared process with keys for several tenants can expose
all of them if compromised. Deployments requiring isolation between mutually
untrusted tenants SHOULD use separate credential-bearing workers or an
equivalent isolation boundary. A signing service or non-exportable key limits
extraction, but a compromised authorized caller may still misuse it; the key
service needs its own operation and audience checks.
