package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterAuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterAuthentication `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
type ClusterAuthentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ClusterAuthenticationSpec   `json:"spec"`
	Status            ClusterAuthenticationStatus `json:"status,omitempty"`
}

type ClusterAuthenticationSpec struct {

	// WebhookTokenAuthnConfig, if present configures remote token reviewers
	WebhookTokenAuthenticators []WebhookTokenAuthenticator `json:"webhookTokenAuthenticators"`

	// TODO (ericavonb): find out how/where used
	// UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be
	// handled. THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
	UserAgentMatchingConfig UserAgentMatchingConfig `json:"userAgentMatchingConfig"`

	// TODO (ericavonb): figure out what to do here
	// OAuthMetadataFile is a path to a file containing the discovery endpoint for the
	// OAuth 2.0 Authorization Server Metadata for an external OAuth server.
	// See IETF Draft: // https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
	// This option is mutually exclusive with OAuthConfig
	OAuthMetadataFile string `json:"oauthMetadataFile"`

	// OAuthConfig contains config options for the built-in oauth server
	// if set, an oauth server will be started up at the /oauth endpoint in the master api server
	OAuthConfig *OAuthConfig `json:"oauthConfig"`
}

type ClusterAuthenticationStatus struct {
	Ok bool `json:"ok"` // TEMPORARY
	// Fill me
}

////////////////////////////////////////////////////////////////////////////////////////

// RemoteConnectionInfo holds information necessary for establishing a remote connection
type RemoteConnectionInfo struct {
	// URL is the remote URL to connect to
	URL string `json:"url"`
	// CA is the CA for verifying TLS connections
	CA string `json:"ca"`
	// CertInfo is the TLS client cert information to present
	// this is anonymous so that we can inline it for serialization
	CertInfo `json:",inline"`
}

// CertInfo holds file locations for cert and key
type CertInfo struct {
	// CertFile is a file containing a PEM-encoded certificate
	CertFile string
	// KeyFile is a file containing a PEM-encoded private key for the certificate specified by CertFile
	KeyFile string
}

// WebhookTokenAuthenticators holds the necessary configuation options for
// external token authenticators
type WebhookTokenAuthenticator struct {
	// RemoteConnectionInfo contains information about how to connect to the external basic auth
	// server
	RemoteConnectionInfo `json:",inline"`

	// CacheTTL indicates how long an authentication result should be cached.
	// It takes a valid time duration string (e.g. "5m").
	// If empty, you get a default timeout of 2 minutes.
	// If zero (e.g. "0m"), caching is disabled
	CacheTTL string `json:"cacheTTL"`
}

// UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be
// handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
type UserAgentMatchingConfig struct {
	// RequiredClients restricts API access via a whitelist of UserAgentMatchRules
	// If this list is non-empty, then a User-Agent MUST match *at least one* regexp applying to
	//   the HTTP verb to be allowed.
	// An empty list means "allow all" and no restrictions will be applied.
	RequiredClients []UserAgentMatchRule `json:"requiredClients"`

	// DeniedClients restricts API access via a blacklist of UserAgentMatchRules
	// If this list is non-empty, then a User-Agent MUST NOT match *any* of regexp applying to
	//   the HTTP verb to be allowed. Any matches will be denied.
	// An empty list means "allow all" and no restrictions will be applied.
	DeniedClients []UserAgentDenyRule `json:"deniedClients"`

	// DefaultRejectionMessage is the message shown when rejecting a client.
	// If not set, a generic message is given.
	DefaultRejectionMessage string `json:"defaultRejectionMessage"`
}

// UserAgentMatchRule describes how to match a given request based on User-Agent and HTTPVerb
type UserAgentMatchRule struct {
	// UserAgentRegex is a regex that is checked against the User-Agent.
	// Known variants of oc clients

	// |-------------------|-----------|---------------------------------------------------|
	// |                   | Resource  |                                                   |
	// |                   | type      |                                                   |
	// | Client            | accessed  | User-Agent                                        |
	// |===================|===========|===================================================|
	// | oc                | Kube      |        oc/v1.2.0 (linux/amd64) kubernetes/bc4550d |
	// |                   | OpenShift |        oc/v1.1.3 (linux/amd64) openshift/b348c2f  |
	// |-------------------|-----------|---------------------------------------------------|
	// | openshift kubectl | Kube      | openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d |
	// |                   | OpenShift | openshift/v1.1.3 (linux/amd64) openshift/b348c2f  |
	// |-------------------|-----------|---------------------------------------------------|
	// | oadm              | Kube      |      oadm/v1.2.0 (linux/amd64) kubernetes/bc4550d |
	// |                   | OpenShift |      oadm/v1.1.3 (linux/amd64) openshift/b348c2f  |
	// |-------------------|-----------|---------------------------------------------------|
	// | openshift cli     | Kube      | openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d |
	// |                   | OpenShift | openshift/v1.1.3 (linux/amd64) openshift/b348c2f  |
	// |-------------------|-----------|---------------------------------------------------|

	Regex string `json:"regex"`

	// HTTPVerbs specifies which HTTP verbs should be matched.  An empty list means "match all verbs".
	HTTPVerbs []string `json:"httpVerbs"`
}

// UserAgentDenyRule adds a rejection message that can be used to help a user figure out how to get an approved client
type UserAgentDenyRule struct {
	UserAgentMatchRule `json:",inline"`

	// RejectionMessage is the message shown when rejecting a client.  If it is not a set, the default message is used.
	RejectionMessage string `json:"rejectionMessage"`
}

//////////////////////////////////////////////
// OAuthServer and Identity Provider Config //
//////////////////////////////////////////////

// OAuthConfig holds the necessary configuration options for OAuth authentication
type OAuthConfig struct {
	//IdentityProviders is an ordered list of ways for a user to identify themselves
	IdentityProviders []IdentityProvider `json:"identityProviders"`

	// GrantConfig describes how to handle grants
	GrantConfig GrantConfig `json:"grantConfig"`

	// TokenConfig contains options for authorization and access tokens
	TokenConfig TokenConfig `json:"tokenConfig"`

	// Templates allow you to customize pages like the login page.
	Templates *OAuthTemplates `json:"templates"`
}

// OAuthTemplates allow for customization of pages like the login page
type OAuthTemplates struct {
	// Login is a path to a file containing a go template used to render the login page.
	// If unspecified, the default login page is used.
	Login string `json:"login"`

	// ProviderSelection is a path to a file containing a go template used to render the provider selection page.
	// If unspecified, the default provider selection page is used.
	ProviderSelection string `json:"providerSelection"`

	// Error is a path to a file containing a go template used to render error pages during the authentication or grant flow
	// If unspecified, the default error page is used.
	Error string `json:"error"`
}

// GrantHandlerType are the valid strategies for handling grant requests
type GrantHandlerType string

const (
	// GrantHandlerAuto auto-approves client authorization grant requests
	GrantHandlerAuto GrantHandlerType = "auto"
	// GrantHandlerPrompt prompts the user to approve new client authorization grant requests
	GrantHandlerPrompt GrantHandlerType = "prompt"
	// GrantHandlerDeny auto-denies client authorization grant requests
	GrantHandlerDeny GrantHandlerType = "deny"
)

// GrantConfig holds the necessary configuration options for grant handlers
type GrantConfig struct {
	// Method: allow, deny, prompt
	Method GrantHandlerType

	// ServiceAccountMethod is used for determining client authorization for service account oauth client.
	// It must be either: deny, prompt
	ServiceAccountMethod GrantHandlerType
}

var ValidGrantHandlerTypes = sets.NewString(string(GrantHandlerAuto), string(GrantHandlerPrompt), string(GrantHandlerDeny))
var ValidServiceAccountGrantHandlerTypes = sets.NewString(string(GrantHandlerPrompt), string(GrantHandlerDeny))

// TokenConfig holds the necessary configuration options for authorization and access tokens
type TokenConfig struct {
	// AuthorizeTokenMaxAgeSeconds defines the maximum age of authorize tokens
	AuthorizeTokenMaxAgeSeconds int32 `json:"authorizeTokenMaxAgeSeconds"`
	// AccessTokenMaxAgeSeconds defines the maximum age of access tokens
	AccessTokenMaxAgeSeconds int32 `json:"accessTokenMaxAgeSeconds"`
	// AccessTokenInactivityTimeoutSeconds defined the default token
	// inactivity timeout for tokens granted by any client.
	// Setting it to nil means the feature is completely disabled (default)
	// The default setting can be overriden on OAuthClient basis.
	// The value represents the maximum amount of time that can occur between
	// consecutive uses of the token. Tokens become invalid if they are not
	// used within this temporal window. The user will need to acquire a new
	// token to regain access once a token times out.
	// Valid values are:
	// - 0: Tokens never time out
	// - X: Tokens time out if there is no activity for X seconds
	// The current minimum allowed value for X is 300 (5 minutes)
	AccessTokenInactivityTimeoutSeconds *int32 `json:"accessTokenInactivityTimeoutSeconds,omitempty"`
}

// IdentityProvider provides identities for users authenticating using credentials
type IdentityProvider struct {
	// Name is used to qualify the identities returned by this provider
	Name string `json:"name"`
	// UseAsChallenger indicates whether to issue WWW-Authenticate challenges for this provider
	UseAsChallenger bool `json:"challenge"`
	// UseAsLogin indicates whether to use this identity provider for unauthenticated browsers to login against
	UseAsLogin bool `json:"login"`
	// MappingMethod determines how identities from this provider are mapped to users
	MappingMethod string `json:"mappingMethod"`
	// Provider contains the information about how to set up a specific identity provider
	Provider runtime.RawExtension `json:"provider"`

	// Method determines the default strategy to use when an OAuth client requests a grant.
	// This method will be used only if the specific OAuth client doesn't provide a strategy
	// of their own. Valid grant handling methods are:
	//  - auto:   always approves grant requests, useful for trusted clients
	//  - prompt: prompts the end user for approval of grant requests, useful for third-party clients
	//  - deny:   always denies grant requests, useful for black-listed clients
	// Defaults to "prompt" if not set.
	Method GrantHandlerType `json:"method"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BasicAuthPasswordIdentityProvider provides identities for users authenticating using HTTP basic auth credentials
type BasicAuthPasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// RemoteConnectionInfo contains information about how to connect to the external basic auth server
	RemoteConnectionInfo `json:",inline"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AllowAllPasswordIdentityProvider provides identities for users authenticating using non-empty passwords
type AllowAllPasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DenyAllPasswordIdentityProvider provides no identities for users
type DenyAllPasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HTPasswdPasswordIdentityProvider provides identities for users authenticating using htpasswd credentials
type HTPasswdPasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// TODO (ericavonb):
	// File is a reference to your htpasswd file
	File string `json:"file"`
}

// StringSource allows specifying a string inline, or externally via env var or file.
// When it contains only a string value, it marshals to a simple JSON string.
type StringSource struct {
	// StringSourceSpec specifies the string value, or external location
	StringSourceSpec
}

// StringSourceSpec specifies a string value, or external location
type StringSourceSpec struct {
	// Value specifies the cleartext value, or an encrypted value if keyFile is specified.
	Value string

	// Env specifies an envvar containing the cleartext value, or an encrypted value if the keyFile is specified.
	Env string

	// File references a file containing the cleartext value, or an encrypted value if a keyFile is specified.
	File string

	// KeyFile references a file containing the key to use to decrypt the value.
	KeyFile string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LDAPPasswordIdentityProvider provides identities for users authenticating using LDAP credentials
type LDAPPasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`
	// URL is an RFC 2255 URL which specifies the LDAP search parameters to use. The syntax of the URL is
	//    ldap://host:port/basedn?attribute?scope?filter
	URL string `json:"url"`
	// BindDN is an optional DN to bind with during the search phase.
	BindDN string `json:"bindDN"`
	// BindPassword is an optional password to bind with during the search phase.
	BindPassword StringSource `json:"bindPassword"`

	// Insecure, if true, indicates the connection should not use TLS.
	// Cannot be set to true with a URL scheme of "ldaps://"
	// If false, "ldaps://" URLs connect using TLS, and "ldap://" URLs are upgraded to a TLS connection using StartTLS as specified in https://tools.ietf.org/html/rfc2830
	Insecure bool `json:"insecure"`
	// CA is the optional trusted certificate authority bundle to use when making requests to the server
	// If empty, the default system roots are used
	CA string `json:"ca"`
	// Attributes maps LDAP attributes to identities
	Attributes LDAPAttributeMapping `json:"attributes"`
}

// LDAPAttributeMapping maps LDAP attributes to OpenShift identity fields
type LDAPAttributeMapping struct {
	// ID is the list of attributes whose values should be used as the user ID. Required.
	// LDAP standard identity attribute is "dn"
	ID []string `json:"id"`
	// PreferredUsername is the list of attributes whose values should be used as the preferred username.
	// LDAP standard login attribute is "uid"
	PreferredUsername []string `json:"preferredUsername"`
	// Name is the list of attributes whose values should be used as the display name. Optional.
	// If unspecified, no display name is set for the identity
	// LDAP standard display name attribute is "cn"
	Name []string `json:"name"`
	// Email is the list of attributes whose values should be used as the email address. Optional.
	// If unspecified, no email is set for the identity
	Email []string `json:"email"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KeystonePasswordIdentityProvider provides identities for users authenticating using keystone password credentials
type KeystonePasswordIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`
	// RemoteConnectionInfo contains information about how to connect to the keystone server
	RemoteConnectionInfo `json:",inline"`
	// Domain Name is required for keystone v3
	DomainName string `json:"domainName"`
	// LegacyLookupByUsername flag indicates that user should be authenticated by username, not keystone ID
	// DEPRECATED - only use this option for legacy systems to ensure backwards compatibiity
	LegacyLookupByUsername bool `json:"useKeystoneIdentity"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RequestHeaderIdentityProvider provides identities for users authenticating using request header credentials
type RequestHeaderIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// LoginURL is a URL to redirect unauthenticated /authorize requests to
	// Unauthenticated requests from OAuth clients which expect interactive logins will be redirected here
	// ${url} is replaced with the current URL, escaped to be safe in a query parameter
	//   https://www.example.com/sso-login?then=${url}
	// ${query} is replaced with the current query string
	//   https://www.example.com/auth-proxy/oauth/authorize?${query}
	LoginURL string `json:"loginURL"`

	// ChallengeURL is a URL to redirect unauthenticated /authorize requests to
	// Unauthenticated requests from OAuth clients which expect WWW-Authenticate challenges will be redirected here
	// ${url} is replaced with the current URL, escaped to be safe in a query parameter
	//   https://www.example.com/sso-login?then=${url}
	// ${query} is replaced with the current query string
	//   https://www.example.com/auth-proxy/oauth/authorize?${query}
	ChallengeURL string `json:"challengeURL"`

	// ClientCA is a file with the trusted signer certs.  If empty, no request verification is done, and any direct request to the OAuth server can impersonate any identity from this provider, merely by setting a request header.
	ClientCA string `json:"clientCA"`
	// ClientCommonNames is an optional list of common names to require a match from. If empty, any client certificate validated against the clientCA bundle is considered authoritative.
	ClientCommonNames []string `json:"clientCommonNames"`

	// Headers is the set of headers to check for identity information
	Headers []string `json:"headers"`
	// PreferredUsernameHeaders is the set of headers to check for the preferred username
	PreferredUsernameHeaders []string `json:"preferredUsernameHeaders"`
	// NameHeaders is the set of headers to check for the display name
	NameHeaders []string `json:"nameHeaders"`
	// EmailHeaders is the set of headers to check for the email address
	EmailHeaders []string `json:"emailHeaders"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GitHubIdentityProvider provides identities for users authenticating using GitHub credentials
type GitHubIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// ClientID is the oauth client ID
	ClientID string `json:"clientID"`
	// ClientSecret is the oauth client secret
	ClientSecret StringSource `json:"clientSecret"`
	// Organizations optionally restricts which organizations are allowed to log in
	Organizations []string `json:"organizations"`
	// Teams optionally restricts which teams are allowed to log in. Format is <org>/<team>.
	Teams []string `json:"teams"`
	// Hostname is the optional domain (e.g. "mycompany.com") for use with a hosted instance of GitHub Enterprise.
	// It must match the GitHub Enterprise settings value that is configured at /setup/settings#hostname.
	Hostname string `json:"hostname"`
	// CA is the optional trusted certificate authority bundle to use when making requests to the server.
	// If empty, the default system roots are used.  This can only be configured when hostname is set to a non-empty value.
	CA string `json:"ca"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GitLabIdentityProvider provides identities for users authenticating using GitLab credentials
type GitLabIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// CA is the optional trusted certificate authority bundle to use when making requests to the server
	// If empty, the default system roots are used
	CA string `json:"ca"`
	// URL is the oauth server base URL
	URL string `json:"url"`
	// ClientID is the oauth client ID
	ClientID string `json:"clientID"`
	// ClientSecret is the oauth client secret
	ClientSecret StringSource `json:"clientSecret"`
	// LegacyOAuth2 determines that OAuth2 should be used, not OIDC
	LegacyOAuth2 bool `json:"legacy,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GoogleIdentityProvider provides identities for users authenticating using Google credentials
type GoogleIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// ClientID is the oauth client ID
	ClientID string `json:"clientID"`
	// ClientSecret is the oauth client secret
	ClientSecret StringSource `json:"clientSecret"`

	// HostedDomain is the optional Google App domain (e.g. "mycompany.com") to restrict logins to
	HostedDomain string `json:"hostedDomain"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OpenIDIdentityProvider provides identities for users authenticating using OpenID credentials
type OpenIDIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// CA is the optional trusted certificate authority bundle to use when making requests to the server
	// If empty, the default system roots are used
	CA string `json:"ca"`

	// ClientID is the oauth client ID
	ClientID string `json:"clientID"`
	// ClientSecret is the oauth client secret
	ClientSecret StringSource `json:"clientSecret"`

	// ExtraScopes are any scopes to request in addition to the standard "openid" scope.
	ExtraScopes []string `json:"extraScopes"`

	// ExtraAuthorizeParameters are any custom parameters to add to the authorize request.
	ExtraAuthorizeParameters map[string]string `json:"extraAuthorizeParameters"`

	// URLs to use to authenticate
	URLs OpenIDURLs `json:"urls"`

	// Claims mappings
	Claims OpenIDClaims `json:"claims"`
}

// OpenIDURLs are URLs to use when authenticating with an OpenID identity provider
type OpenIDURLs struct {
	// Authorize is the oauth authorization URL
	Authorize string `json:"authorize"`
	// Token is the oauth token granting URL
	Token string `json:"token"`
	// UserInfo is the optional userinfo URL.
	// If present, a granted access_token is used to request claims
	// If empty, a granted id_token is parsed for claims
	UserInfo string `json:"userInfo"`
}

// UserIDClaim is used in the `ID` field for an `OpenIDClaim`
// Per http://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
//  "The sub (subject) and iss (issuer) Claims, used together, are the only Claims that an RP can
//   rely upon as a stable identifier for the End-User, since the sub Claim MUST be locally unique
//   and never reassigned within the Issuer for a particular End-User, as described in Section 2.
//   Therefore, the only guaranteed unique identifier for a given End-User is the combination of the
//   iss Claim and the sub Claim."
const UserIDClaim = "sub"

// OpenIDClaims contains a list of OpenID claims to use when authenticating with an OpenID identity provider
type OpenIDClaims struct {
	// PreferredUsername is the list of claims whose values should be used as the preferred username.
	// If unspecified, the preferred username is determined from the value of the id claim
	PreferredUsername []string `json:"preferredUsername"`
	// Name is the list of claims whose values should be used as the display name. Optional.
	// If unspecified, no display name is set for the identity
	Name []string `json:"name"`
	// Email is the list of claims whose values should be used as the email address. Optional.
	// If unspecified, no email is set for the identity
	Email []string `json:"email"`
}
