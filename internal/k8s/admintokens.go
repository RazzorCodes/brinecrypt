package k8s

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"brinecrypt/internal/logger"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var adminTokens atomic.Value // stores []string

func IsBootstrapToken(token string) bool {
	if token == "" {
		return false
	}
	tokens, _ := adminTokens.Load().([]string)
	for _, t := range tokens {
		if t == token {
			return true
		}
	}
	return false
}

func StartAdminTokenSync(ctx context.Context) {
	ns := os.Getenv("BRINECRYPT_SYNC_NAMESPACE")
	name := os.Getenv("BRINECRYPT_ADMIN_TOKENS_CONFIGMAP")
	if ns == "" || name == "" {
		logger.Info("admin token sync disabled: BRINECRYPT_ADMIN_TOKENS_CONFIGMAP not set")
		return
	}
	go watchAdminTokens(ctx, ns, name)
}

func watchAdminTokens(ctx context.Context, ns, name string) {
	c, err := getClient()
	if err != nil {
		logger.Error("admin token sync: k8s client unavailable: " + err.Error())
		return
	}

	cm, err := c.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		logger.Error("admin token sync: initial configmap fetch: " + err.Error())
	} else {
		applyAdminTokens(cm.Data["admin_tokens"])
	}

	for {
		watcher, err := c.CoreV1().ConfigMaps(ns).Watch(ctx, metav1.ListOptions{
			FieldSelector: "metadata.name=" + name,
		})
		if err != nil {
			logger.Error("admin token sync: watch failed: " + err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		func() {
			defer watcher.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-watcher.ResultChan():
					if !ok {
						logger.Warn("admin token sync: watch channel closed, reconnecting")
						return
					}
					if cm, ok := event.Object.(*corev1.ConfigMap); ok {
						applyAdminTokens(cm.Data["admin_tokens"])
					}
				}
			}
		}()

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func applyAdminTokens(data string) {
	if data == "" {
		adminTokens.Store([]string{})
		return
	}
	var tokens []string
	if err := json.Unmarshal([]byte(data), &tokens); err != nil {
		logger.Error("admin token sync: parse failed: " + err.Error())
		return
	}
	adminTokens.Store(tokens)
	logger.Info("admin token sync: loaded " + strconv.Itoa(len(tokens)) + " token(s)")
}
