package v1alpha1

import (
	sdkK8sutil "github.com/operator-framework/operator-sdk/pkg/util/k8sutil"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	version   = "v1alpha1"
	groupName = "auth.config.openshift.io"

	ClusterAuthenticationKind     = "ClusterAuthentication"
	ClusterAuthenticationListKind = "ClusterAuthenticationList"
)

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
	// SchemeGroupVersion is the group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: groupName, Version: version}
)

// Resource takes an unqualified resource and returns a Group-qualified GroupResource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
func init() {
	sdkK8sutil.AddToSDKScheme(AddToScheme)
}

// addKnownTypes adds the set of types defined in this package to the supplied scheme.

// addKnownTypes adds the set of types defined in this package to the supplied scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypeWithName(
		SchemeGroupVersion.WithKind(ClusterAuthenticationKind),
		&ClusterAuthentication{},
	)
	scheme.AddKnownTypeWithName(
		SchemeGroupVersion.WithKind(ClusterAuthenticationListKind),
		&ClusterAuthenticationList{},
	)
	scheme.AddKnownTypes(SchemeGroupVersion,
		&AllowAllPasswordIdentityProvider{},
		&DenyAllPasswordIdentityProvider{},
		&HTPasswdPasswordIdentityProvider{},
		&LDAPPasswordIdentityProvider{},
		&KeystonePasswordIdentityProvider{},
		&RequestHeaderIdentityProvider{},
		&GitHubIdentityProvider{},
		&GitLabIdentityProvider{},
		&GoogleIdentityProvider{},
		&OpenIDIdentityProvider{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
