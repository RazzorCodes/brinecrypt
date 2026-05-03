package operator

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "brinekey.brinecrypt.io", Version: "v1alpha1"}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=brinecryptsecrets,scope=Namespaced,shortName=bcs
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="LastSync",type=string,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type BrinecryptSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BrinecryptSecretSpec   `json:"spec,omitempty"`
	Status BrinecryptSecretStatus `json:"status,omitempty"`
}

type BrinecryptSecretSpec struct {
	RemotePath      string `json:"remotePath"`
	ServiceAccount  string `json:"serviceAccount"`
	TargetSecret    string `json:"targetSecret"`
	SecretKey       string `json:"secretKey,omitempty"`
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

type BrinecryptSecretStatus struct {
	Ready        bool         `json:"ready"`
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	LastError    string       `json:"lastError,omitempty"`
}

// +kubebuilder:object:root=true
type BrinecryptSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BrinecryptSecret `json:"items"`
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&BrinecryptSecret{},
		&BrinecryptSecretList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
