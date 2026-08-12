# Deploying GateBroker

The manifests here are a complete, minimal reference. They use only core
Kubernetes objects so the deployment contract stays readable; adapt them to
whatever Helm chart, Kustomize overlay, or GitOps tooling you already run.

```shell
kubectl apply -f entitlements-example.yaml   # replace the placeholders first
kubectl apply -f gatebroker.yaml
```

## What the deployment has to provide

**A non-secret policy document.** `policies.json` maps identity-provider groups
or app roles to allowed models and names the key each policy needs. It never
contains a key value.

**One file per referenced key.** With `GABRO_KEY_DIR` set, the broker resolves a
policy's `key_ref` to a file of that name in that directory. Anything that
presents files works: a Secret volume, an external secret manager, a CSI driver,
a sidecar-written tmpfs. Without `GABRO_KEY_DIR`, the reference is read from the
process environment instead.

**Restart on rotation.** Policies are loaded once at startup, so rotating the
projected document requires restarting the pod. Any reloader that watches the
projected Secret will do; without one, roll the Deployment yourself.

**Network restriction.** Nothing here restricts traffic. The broker is only a
useful boundary if callers cannot bypass it and reach the upstream gateway
directly. Enforce that with a NetworkPolicy (or your CNI's equivalent) that
allows the gateway to accept traffic from the broker's pod identity and from
nothing else, and route the client-facing `/v1/*` paths to the broker rather
than to the gateway.

**TLS termination and ingress.** The container serves plain HTTP on port 8080 and
expects to sit behind an ingress, gateway, or service mesh that terminates TLS.

## Readiness

`GET /healthz` returns `{"status": "ok"}` and nothing else. `GET /readyz`
succeeds only while the JWKS snapshot is fresh and every policy-referenced key
resolves to a non-empty value; otherwise it returns a non-disclosing `503`.
Neither endpoint makes a model call or reveals configuration.

A pod that never becomes ready almost always means one of: the JWKS endpoint is
unreachable from the pod, or a `key_ref` in the policy document has no
corresponding file in `GABRO_KEY_DIR`.

## Scaling

The bundled rate limiter is a process-local fixed window, so it bounds one
replica only. Running more than one replica multiplies the effective limit by the
replica count. Inject a shared limiter through
`gatebroker.forwarding.create_app` before scaling out.
