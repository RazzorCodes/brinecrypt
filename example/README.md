# Brinekey example manifests

This directory contains a minimal end-to-end example:

1. `namespace-and-sa.yaml`
   - Creates namespace `test-ns`
   - Creates ServiceAccount `test-sa`

2. `brinecryptsecret.yaml`
   - Creates a `BrinecryptSecret` named `brinekey-test`
   - Fetches `remotePath: test-ns/test-rs` from brinecrypt
   - Writes value into Kubernetes Secret `brinekey-test-secret` key `value`

3. `consumer-deployment.yaml`
   - Example pod that consumes the synced secret via env var and mounted file

## Prerequisites

- Brinecrypt + brinekey operator installed and running
- SA permissions in `brinecrypt-sa-permissions` include:
  - `test-ns/test-sa` has `read` on `test-ns/test-rs`
- Resource `test-ns/test-rs` exists in brinecrypt

## Apply

```/dev/null/bash#L1-4
kubectl apply -f example/brinekey/namespace-and-sa.yaml
kubectl apply -f example/brinekey/brinecryptsecret.yaml
kubectl apply -f example/brinekey/consumer-deployment.yaml
kubectl get brinecryptsecret -n test-ns brinekey-test -o yaml
```

## Verify extracted value

```/dev/null/bash#L1-6
kubectl get secret -n test-ns brinekey-test-secret -o jsonpath='{.data.value}' | base64 -d && echo
kubectl get pods -n test-ns -l app=brinekey-consumer
kubectl logs -n test-ns deploy/brinekey-consumer
kubectl exec -n test-ns deploy/brinekey-consumer -- cat /var/run/brinekey/value
kubectl exec -n test-ns deploy/brinekey-consumer -- printenv BRINEKEY_VALUE
```
