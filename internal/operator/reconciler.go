package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	defaultRefreshInterval = time.Hour
	minimumRefreshInterval = time.Second
	defaultSecretKey       = "value"
	tokenAudience          = "brinekey"
	tokenTTLSeconds        = int64(600)
)

type BrinecryptSecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	KubeClientset kubernetes.Interface
	BrinecryptURL string
	HTTPClient    *http.Client
}

type brinecryptResourceResponse struct {
	Value *struct {
		Data string `json:"data"`
	} `json:"value"`
}

func (r *BrinecryptSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("name", req.Name, "namespace", req.Namespace)
	log.Info("reconcile start")

	var obj BrinecryptSecret
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if client.IgnoreNotFound(err) == nil {
			log.Info("resource not found; skipping")
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get resource")
		return ctrl.Result{}, err
	}

	refresh, err := parseRefreshInterval(obj.Spec.RefreshInterval)
	if err != nil {
		log.Error(err, "invalid refresh interval", "refreshInterval", obj.Spec.RefreshInterval)
		return r.fail(ctx, &obj, err)
	}

	secretKey := obj.Spec.SecretKey
	if secretKey == "" {
		secretKey = defaultSecretKey
	}

	if obj.Spec.RemotePath == "" || obj.Spec.ServiceAccount == "" || obj.Spec.TargetSecret == "" {
		err := fmt.Errorf("spec.remotePath, spec.serviceAccount, and spec.targetSecret are required")
		log.Error(err, "invalid spec")
		return r.fail(ctx, &obj, err)
	}

	log.Info("requesting service account token", "serviceAccount", obj.Spec.ServiceAccount, "audience", tokenAudience)
	ttl := tokenTTLSeconds
	tok, err := r.KubeClientset.CoreV1().ServiceAccounts(obj.Namespace).CreateToken(ctx, obj.Spec.ServiceAccount, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{tokenAudience},
			ExpirationSeconds: &ttl,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		log.Error(err, "token request failed", "serviceAccount", obj.Spec.ServiceAccount)
		return r.fail(ctx, &obj, fmt.Errorf("token request failed: %w", err))
	}

	log.Info("fetching remote value from brinecrypt", "remotePath", obj.Spec.RemotePath)
	value, err := r.fetchRemoteSecretValue(ctx, obj.Spec.RemotePath, tok.Status.Token)
	if err != nil {
		log.Error(err, "brinecrypt fetch failed", "remotePath", obj.Spec.RemotePath)
		return r.fail(ctx, &obj, err)
	}

	var outSecret corev1.Secret
	err = r.Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: obj.Spec.TargetSecret}, &outSecret)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "failed to get target secret", "targetSecret", obj.Spec.TargetSecret)
			return r.fail(ctx, &obj, fmt.Errorf("get target secret failed: %w", err))
		}
		log.Info("target secret not found, creating", "targetSecret", obj.Spec.TargetSecret)
		outSecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      obj.Spec.TargetSecret,
				Namespace: obj.Namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{},
		}
	} else if outSecret.Data == nil {
		outSecret.Data = map[string][]byte{}
	}

	outSecret.Type = corev1.SecretTypeOpaque
	outSecret.Data[secretKey] = []byte(value)

	if err := controllerutil.SetControllerReference(&obj, &outSecret, r.Scheme); err != nil {
		log.Error(err, "failed to set owner reference", "targetSecret", obj.Spec.TargetSecret)
		return r.fail(ctx, &obj, fmt.Errorf("set owner reference failed: %w", err))
	}

	if outSecret.CreationTimestamp.IsZero() {
		if err := r.Create(ctx, &outSecret); err != nil {
			log.Error(err, "failed to create target secret", "targetSecret", obj.Spec.TargetSecret)
			return r.fail(ctx, &obj, fmt.Errorf("create target secret failed: %w", err))
		}
		log.Info("created target secret", "targetSecret", obj.Spec.TargetSecret, "secretKey", secretKey)
	} else {
		if err := r.Update(ctx, &outSecret); err != nil {
			log.Error(err, "failed to update target secret", "targetSecret", obj.Spec.TargetSecret)
			return r.fail(ctx, &obj, fmt.Errorf("update target secret failed: %w", err))
		}
		log.Info("updated target secret", "targetSecret", obj.Spec.TargetSecret, "secretKey", secretKey)
	}

	now := metav1.Now()
	obj.Status.Ready = true
	obj.Status.LastError = ""
	obj.Status.LastSyncTime = &now
	if err := r.Status().Update(ctx, &obj); err != nil {
		log.Error(err, "failed to update ready status")
		return ctrl.Result{}, err
	}

	log.Info("reconcile success", "requeueAfter", refresh.String())
	return ctrl.Result{RequeueAfter: refresh}, nil
}

func (r *BrinecryptSecretReconciler) fail(ctx context.Context, obj *BrinecryptSecret, err error) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("name", obj.Name, "namespace", obj.Namespace)
	obj.Status.Ready = false
	obj.Status.LastError = err.Error()
	if statusErr := r.Status().Update(ctx, obj); statusErr != nil {
		log.Error(statusErr, "failed to update failure status", "originalError", err.Error())
		return ctrl.Result{}, fmt.Errorf("reconcile error: %v; status update error: %w", err, statusErr)
	}
	log.Error(err, "reconcile failed")
	return ctrl.Result{}, err
}

func parseRefreshInterval(in string) (time.Duration, error) {
	if in == "" {
		return defaultRefreshInterval, nil
	}
	d, err := time.ParseDuration(in)
	if err != nil {
		return 0, fmt.Errorf("invalid refreshInterval: %w", err)
	}
	if d < minimumRefreshInterval {
		return 0, fmt.Errorf("refreshInterval must be >= %s", minimumRefreshInterval)
	}
	return d, nil
}

func (r *BrinecryptSecretReconciler) fetchRemoteSecretValue(ctx context.Context, remotePath, jwt string) (string, error) {
	base := strings.TrimRight(r.BrinecryptURL, "/")
	url := fmt.Sprintf("%s/api/v1/resource?op=query", base)

	parts := strings.SplitN(remotePath, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("remotePath must be namespace/name, got %q", remotePath)
	}
	bodyBytes, err := json.Marshal(map[string]string{"namespace": parts[0], "name": parts[1]})
	if err != nil {
		return "", fmt.Errorf("marshal request body failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("build brinecrypt request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("brinecrypt request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("brinecrypt returned status %d: %s", resp.StatusCode, string(body))
	}

	var payload brinecryptResourceResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode brinecrypt response failed: %w", err)
	}
	if payload.Value == nil {
		return "", fmt.Errorf("brinecrypt response missing value")
	}

	return payload.Value.Data, nil
}

func (r *BrinecryptSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&BrinecryptSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
