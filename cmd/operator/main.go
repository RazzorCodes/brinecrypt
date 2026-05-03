package main

import (
	"net/http"
	"os"
	"time"

	"brinecrypt/internal/operator"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(operator.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         true,
		LeaderElectionID:       "brinekey.brinecrypt.io",
		Metrics:                server.Options{BindAddress: "0"},
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		panic(err)
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}

	brinecryptURL := os.Getenv("BRINEKEY_BRINECRYPT_URL")
	if brinecryptURL == "" {
		brinecryptURL = "http://brinecrypt:8080"
	}

	reconciler := &operator.BrinecryptSecretReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		KubeClientset: cs,
		BrinecryptURL: brinecryptURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		panic(err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		panic(err)
	}
}
