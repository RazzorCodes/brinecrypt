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

var allowedOrigins atomic.Value // stores []string

func AllowedOrigins() []string {
	v, _ := allowedOrigins.Load().([]string)
	return v
}

func StartCORSSync(ctx context.Context) {
	ns := os.Getenv("BRINECRYPT_SYNC_NAMESPACE")
	name := os.Getenv("BRINECRYPT_CORS_CONFIGMAP")
	if ns == "" || name == "" {
		return
	}
	go watchCORSOrigins(ctx, ns, name)
}

func watchCORSOrigins(ctx context.Context, ns, name string) {
	c, err := getClient()
	if err != nil {
		logger.Error("cors sync: k8s client unavailable: " + err.Error())
		return
	}

	cm, err := c.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		logger.Error("cors sync: initial configmap fetch: " + err.Error())
	} else {
		applyCORSOrigins(cm.Data["allowed_origins"])
	}

	for {
		watcher, err := c.CoreV1().ConfigMaps(ns).Watch(ctx, metav1.ListOptions{
			FieldSelector: "metadata.name=" + name,
		})
		if err != nil {
			logger.Error("cors sync: watch failed: " + err.Error())
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
						logger.Warn("cors sync: watch channel closed, reconnecting")
						return
					}
					if cm, ok := event.Object.(*corev1.ConfigMap); ok {
						applyCORSOrigins(cm.Data["allowed_origins"])
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

func applyCORSOrigins(data string) {
	if data == "" {
		allowedOrigins.Store([]string{})
		return
	}
	var origins []string
	if err := json.Unmarshal([]byte(data), &origins); err != nil {
		logger.Error("cors sync: parse failed: " + err.Error())
		return
	}
	allowedOrigins.Store(origins)
	logger.Info("cors sync: loaded " + strconv.Itoa(len(origins)) + " origin(s)")
}
