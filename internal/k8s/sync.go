package k8s

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type permissionEntry struct {
	ResourcePattern string `json:"resource_pattern"`
	Verb            string `json:"verb"`
}

type saEntry struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Permissions []permissionEntry `json:"permissions"`
}

type syncConfig struct {
	ServiceAccounts []saEntry `json:"service_accounts"`
}

// StartSync reads BRINECRYPT_SYNC_NAMESPACE and BRINECRYPT_SYNC_CONFIGMAP from the environment.
// If both are set, it spawns a goroutine that watches the ConfigMap and syncs SA permissions on change.
func StartSync(ctx context.Context, db *gorm.DB) {
	cmNamespace := os.Getenv("BRINECRYPT_SYNC_NAMESPACE")
	cmName := os.Getenv("BRINECRYPT_SYNC_CONFIGMAP")
	if cmNamespace == "" || cmName == "" {
		logger.Info("SA sync disabled: BRINECRYPT_SYNC_NAMESPACE or BRINECRYPT_SYNC_CONFIGMAP not set")
		return
	}
	go watchLoop(ctx, db, cmNamespace, cmName)
}

func watchLoop(ctx context.Context, db *gorm.DB, ns, name string) {
	c, err := getClient()
	if err != nil {
		logger.Error("SA sync: k8s client unavailable: " + err.Error())
		return
	}

	cm, err := c.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		logger.Error("SA sync: initial configmap fetch: " + err.Error())
	} else {
		applySync(db, cm.Data["permissions"])
	}

	for {
		watcher, err := c.CoreV1().ConfigMaps(ns).Watch(ctx, metav1.ListOptions{
			FieldSelector: "metadata.name=" + name,
		})
		if err != nil {
			logger.Error("SA sync: watch failed: " + err.Error())
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
						logger.Warn("SA sync: watch channel closed, reconnecting")
						return
					}
					if cm, ok := event.Object.(*corev1.ConfigMap); ok {
						applySync(db, cm.Data["permissions"])
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

func applySync(db *gorm.DB, data string) {
	if data == "" {
		logger.Warn("SA sync: configmap has no 'permissions' key")
		return
	}
	var cfg syncConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		logger.Error("SA sync: parse config: " + err.Error())
		return
	}
	for _, entry := range cfg.ServiceAccounts {
		if err := syncSA(db, entry); err != nil {
			logger.Error("SA sync: " + entry.Namespace + "/" + entry.Name + ": " + err.Error())
		}
	}
}

func syncSA(db *gorm.DB, entry saEntry) error {
	sa, err := store.GetOrCreateSA(db, entry.Namespace, entry.Name)
	if err != nil {
		return err
	}

	var permissions []orm.Permission
	for _, p := range entry.Permissions {
		if err := orm.ValidateResourcePattern(p.ResourcePattern); err != nil {
			logger.Warn("SA sync: invalid pattern " + p.ResourcePattern + ": " + err.Error())
			continue
		}
		v, err := orm.ParseVerb(p.Verb)
		if err != nil {
			logger.Warn("SA sync: invalid verb " + p.Verb + ": " + err.Error())
			continue
		}
		permissions = append(permissions, orm.NewPermission(p.ResourcePattern, v, nil))
	}

	if err := store.ReplaceSAPermissions(db, sa.Id, permissions); err != nil {
		return err
	}
	return store.UpdateSASyncedAt(db, sa.Id)
}
