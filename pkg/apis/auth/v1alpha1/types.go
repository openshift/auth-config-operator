package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterAuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterAuthentication `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterAuthentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ClusterAuthenticationSpec   `json:"spec"`
	Status            ClusterAuthenticationStatus `json:"status,omitempty"`
}

type ClusterAuthenticationSpec struct {
	Ok bool `json:"ok"` // TEMPORARY
	// Fill me
}
type ClusterAuthenticationStatus struct {
	Ok bool `json:"ok"` // TEMPORARY
	// Fill me
}
