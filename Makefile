REGISTRY := zot.lan
IMAGE    := brinecrypt
TAG      := latest

.PHONY: build push deploy helm-upgrade

build:
	podman build -f Dockerfile.prod -t $(REGISTRY)/$(IMAGE):$(TAG) .

push: build
	podman push --tls-verify=false $(REGISTRY)/$(IMAGE):$(TAG)

deploy: push
	kubectl rollout restart deployment/brinecrypt -n kube-ex
	kubectl rollout status deployment/brinecrypt -n kube-ex

helm-upgrade:
	helm upgrade --install brinecrypt ./helm --namespace kube-ex -f helm/values.local.yaml
