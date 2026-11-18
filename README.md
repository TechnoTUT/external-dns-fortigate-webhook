# external-dns-fortigate-webhook

A webhook provider for [ExternalDNS](https://github.com/kubernetes-sigs/external-dns). It writes records from Kubernetes Services, Ingresses and DNSEndpoints to a FortiGate DNS database (`config system dns-database`) through the FortiOS REST API.

TechnoTUT uses it in the cluster defined in [TechnoTUT/Infra](https://github.com/TechnoTUT/Infra) so that the FortiGate answers for `svc.technotut.net` directly.

## How it works

- It runs as a sidecar in the ExternalDNS pod. ExternalDNS calls the webhook API (version 1) on `127.0.0.1:8888`.
- Supported record types: A, AAAA and CNAME in the forward zone, and PTR and PTR_V6 in reverse zones.
- On each change set it reads the zone from the FortiGate, applies the changes and replaces the whole `dns-entry` table of the zone with a single PUT. Nothing is written when the result is unchanged, so the FortiGate only saves its configuration (and adds a config revision) when records actually change.
- When reverse zones are configured, PTR records are derived from the A and AAAA records of the forward zone. The ExternalDNS `--create-ptr` flag is not used. Reverse zones are rebuilt after every change and every `REVERSE_RESYNC_INTERVAL`.
- The only dependency is the Go standard library.

### The zones are dedicated to the webhook

A FortiGate `dns-entry` cannot hold TXT records, so the ExternalDNS TXT registry, which records who owns each record, cannot be used. The webhook therefore works like this:

- Every A, AAAA and CNAME entry in the forward zone and every PTR entry in a reverse zone belongs to the webhook.
- ExternalDNS runs with `--registry=noop`. With `policy: sync`, any record that does not exist in Kubernetes is deleted.
- Do not add static records on the FortiGate by hand. Define them in Kubernetes as `DNSEndpoint` resources instead.
- The webhook never touches the zone apex (`@`), other record types such as NS or MX, or entries with `status disable`.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `FORTIGATE_URL` | (required) | For example `https://192.168.99.129` |
| `FORTIGATE_TOKEN` | | API key of the REST API administrator |
| `FORTIGATE_TOKEN_FILE` | | Read the API key from a file. Takes precedence over `FORTIGATE_TOKEN` |
| `FORTIGATE_TOKEN_IN_QUERY` | `false` | Send the key as the `access_token` query parameter instead of an `Authorization: Bearer` header, for older FortiOS versions that do not accept the header |
| `FORTIGATE_VDOM` | `root` | |
| `FORTIGATE_ZONE` | (required) | Name of the forward zone in `dns-database`. The domain is read from the zone's `domain` field |
| `FORTIGATE_REVERSE_ZONES` | | Comma-separated names of reverse zones in `dns-database`. Their `domain` must be split on octet boundaries (nibble boundaries for IPv6), such as `12.10.in-addr.arpa` |
| `FORTIGATE_CA_FILE` | | CA bundle (PEM) used to verify the FortiGate certificate |
| `FORTIGATE_INSECURE_SKIP_VERIFY` | `false` | Skip certificate verification, for a self-signed certificate |
| `DRY_RUN` | `false` | Log the entries that would be written instead of writing them |
| `REVERSE_RESYNC_INTERVAL` | `5m` | How often reverse zones are rebuilt |
| `WEBHOOK_ADDR` | `127.0.0.1:8888` | Webhook API listen address |
| `HEALTH_ADDR` | `:8080` | `/healthz` and `/readyz` listen address |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

`/readyz` returns 503 until the webhook has read the zones from the FortiGate after startup.

## FortiGate setup

1. Create an admin profile for the REST API administrator. `dns-database` is part of the system configuration group (`sysgrp`).

   ```
   config system accprofile
       edit "externaldns"
           set sysgrp custom
           config sysgrp-permission
               set cfg read-write
           end
       next
   end
   ```

2. Create the REST API administrator and generate an API key. Restrict the trusted hosts to the addresses that pod traffic has after NAT, which are the node addresses.

   ```
   config system api-user
       edit "externaldns"
           set accprofile "externaldns"
           set vdom "root"
           config trusthost
               edit 1
                   set ipv4-trusthost 192.168.99.128 255.255.255.128
               next
           end
       next
   end
   execute api-user generate-key externaldns
   ```

3. Allow HTTPS administrative access on the interface the pods reach the FortiGate through (for example, add `https` to `allowaccess` on `dmz`).

4. Create the zones. Create the reverse zones as well if you want PTR records.

   ```
   config system dns-database
       edit "svc.technotut.net"
           set domain "svc.technotut.net"
           set authoritative enable
           set ttl 300
           set primary-name "ns1"
           set contact "network.technotut.net"
       next
       edit "12.10.in-addr.arpa"
           set domain "12.10.in-addr.arpa"
           set authoritative enable
           set ttl 300
           set primary-name "ns1"
           set contact "network.technotut.net"
       next
   end
   ```

5. Set `config system dns-server` to `recursive` or `non-recursive` on every interface that clients or CoreDNS query. In `forward-only` mode the FortiGate ignores its local DNS database.

## ExternalDNS setup (Helm chart)

```yaml
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/technotut/external-dns-fortigate-webhook
      tag: main
    env:
      - { name: FORTIGATE_URL, value: "https://192.168.99.129" }
      - { name: FORTIGATE_ZONE, value: svc.technotut.net }
      - { name: FORTIGATE_REVERSE_ZONES, value: 12.10.in-addr.arpa }
      - { name: FORTIGATE_INSECURE_SKIP_VERIFY, value: "true" }
      - name: FORTIGATE_TOKEN
        valueFrom:
          secretKeyRef: { name: external-dns-fortigate, key: token }
    livenessProbe:
      httpGet: { path: /healthz, port: http-webhook-metrics }
    readinessProbe:
      httpGet: { path: /readyz, port: http-webhook-metrics }
sources: [service, ingress, crd]
domainFilters: [svc.technotut.net]
policy: sync
registry: noop
managedRecordTypes: [A, AAAA, CNAME]
```

For the first run, set `DRY_RUN=true`. Check in the logs what would be written, then remove it.

## Not yet verified on FortiOS 6.2

The tests run against a fake FortiGate. The following points have not been checked on the real FortiGate-100D (FortiOS 6.2.16):

- Whether authentication with the `Authorization: Bearer` header works. If it does not, set `FORTIGATE_TOKEN_IN_QUERY=true`.
- Whether a PUT that includes `dns-entry` replaces the whole table.
- CNAME `canonical-name` and PTR `hostname` values are written as FQDNs without a trailing dot. Whether the FortiGate answers correctly in that form.

## Development

```sh
go test ./...
podman build -t external-dns-fortigate-webhook -f Containerfile .
```

Pushing to `main` or a `v*` tag makes GitHub Actions push the image to `ghcr.io/technotut/external-dns-fortigate-webhook`. The image is not stored in the in-cluster registry, so that the DNS webhook does not depend on name resolution for that registry.
