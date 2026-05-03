package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"brinecrypt/internal/authz"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	once      sync.Once
	client    *kubernetes.Clientset
	clientErr error
)

func getClient() (*kubernetes.Clientset, error) {
	once.Do(func() {
		config, err := rest.InClusterConfig()
		if err != nil {
			clientErr = err
			return
		}
		client, clientErr = kubernetes.NewForConfig(config)
	})
	return client, clientErr
}

// ValidateSAToken validates a k8s SA JWT via the TokenReview API.
// Returns the SA namespace and name on success.
func ValidateSAToken(ctx context.Context, token string) (namespace, name string, err error) {
	audience := strings.TrimSpace(os.Getenv("BRINECRYPT_SA_TOKEN_AUDIENCE"))
	if audience == "" {
		audience = "brinekey"
	}

	c, err := getClient()
	if err != nil {
		return "", "", fmt.Errorf("k8s client unavailable: %w", err)
	}

	review, err := c.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{audience},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", "", fmt.Errorf("tokenreview failed: %w", err)
	}

	if !review.Status.Authenticated {
		return "", "", fmt.Errorf("token not authenticated")
	}

	subject, err := authz.NormalizeSubject(review.Status.User.Username)
	if err != nil {
		return "", "", fmt.Errorf("not a service account token: %w", err)
	}

	parts := strings.SplitN(subject, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid normalized subject: %q", subject)
	}
	return parts[0], parts[1], nil
}
