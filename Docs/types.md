Auth Config Types
=================

```go
...
// MasterConfig holds the necessary configuration options for the OpenShift master
type MasterConfig struct {
	...
	// AuthConfig configures authentication options in addition to the standard
	// oauth token and client certificate authenticators
	AuthConfig MasterAuthConfig `json:"authConfig"`
	...
	// OAuthConfig, if present start the /oauth endpoint in this process
	OAuthConfig *OAuthConfig `json:"oauthConfig"`
    ...
	// PolicyConfig holds information about where to locate critical pieces of bootstrapping policy
	PolicyConfig PolicyConfig `json:"policyConfig"`
	...
}

// MasterAuthConfig configures authentication options in addition to the standard
// oauth token and client certificate authenticators
type MasterAuthConfig struct {
	// RequestHeader holds options for setting up a front proxy against the the API.  It is optional.
	RequestHeader *RequestHeaderAuthenticationOptions `json:"requestHeader"`
	// WebhookTokenAuthnConfig, if present configures remote token reviewers
	WebhookTokenAuthenticators []WebhookTokenAuthenticator `json:"webhookTokenAuthenticators"`
	// OAuthMetadataFile is a path to a file containing the discovery endpoint for OAuth 2.0 Authorization
	// Server Metadata for an external OAuth server.
	// See IETF Draft: // https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
	// This option is mutually exclusive with OAuthConfig
	OAuthMetadataFile string `json:"oauthMetadataFile"`
}

// RequestHeaderAuthenticationOptions provides options for setting up a front proxy against the entire
// API instead of against the /oauth endpoint.
type RequestHeaderAuthenticationOptions struct {
	// ClientCA is a file with the trusted signer certs.  It is required.
	ClientCA string `json:"clientCA"`
	// ClientCommonNames is a required list of common names to require a match from.
	ClientCommonNames []string `json:"clientCommonNames"`

	// UsernameHeaders is the list of headers to check for user information.  First hit wins.
	UsernameHeaders []string `json:"usernameHeaders"`
	// GroupNameHeader is the set of headers to check for group information.  All are unioned.
	GroupHeaders []string `json:"groupHeaders"`
	// ExtraHeaderPrefixes is the set of request header prefixes to inspect for user extra. X-Remote-Extra- is suggested.
	ExtraHeaderPrefixes []string `json:"extraHeaderPrefixes"`
}
...
//  holds the necessary configuration options for
type PolicyConfig struct {
	// UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
	UserAgentMatchingConfig UserAgentMatchingConfig `json:"userAgentMatchingConfig"`
}

// UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
type UserAgentMatchingConfig struct {
	// If this list is non-empty, then a User-Agent must match one of the UserAgentRegexes to be allowed
	RequiredClients []UserAgentMatchRule `json:"requiredClients"`

	// If this list is non-empty, then a User-Agent must not match any of the UserAgentRegexes
	DeniedClients []UserAgentDenyRule `json:"deniedClients"`

	// DefaultRejectionMessage is the message shown when rejecting a client.  If it is not a set, a generic message is given.
	DefaultRejectionMessage string `json:"defaultRejectionMessage"`
}

// UserAgentMatchRule describes how to match a given request based on User-Agent and HTTPVerb
type UserAgentMatchRule struct {
	// UserAgentRegex is a regex that is checked against the User-Agent.
	// Known variants of oc clients
	// 1. oc accessing kube resources: oc/v1.2.0 (linux/amd64) kubernetes/bc4550d
	// 2. oc accessing openshift resources: oc/v1.1.3 (linux/amd64) openshift/b348c2f
	// 3. openshift kubectl accessing kube resources:  openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d
	// 4. openshift kubectl accessing openshift resources: openshift/v1.1.3 (linux/amd64) openshift/b348c2f
	// 5. oadm accessing kube resources: oadm/v1.2.0 (linux/amd64) kubernetes/bc4550d
	// 6. oadm accessing openshift resources: oadm/v1.1.3 (linux/amd64) openshift/b348c2f
	// 7. openshift cli accessing kube resources: openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d
	// 8. openshift cli accessing openshift resources: openshift/v1.1.3 (linux/amd64) openshift/b348c2f
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
...
// WebhookTokenAuthenticators holds the necessary configuation options for
// external token authenticators
type WebhookTokenAuthenticator struct {
	// ConfigFile is a path to a Kubeconfig file with the webhook configuration
	ConfigFile string `json:"configFile"`
	// CacheTTL indicates how long an authentication result should be cached.
	// It takes a valid time duration string (e.g. "5m").
	// If empty, you get a default timeout of 2 minutes.
	// If zero (e.g. "0m"), caching is disabled
	CacheTTL string `json:"cacheTTL"`
}

// OAuthConfig holds the necessary configuration options for OAuth authentication
type OAuthConfig struct {
	// MasterCA is the CA for verifying the TLS connection back to the MasterURL.
	MasterCA *string `json:"masterCA"`

	// MasterURL is used for making server-to-server calls to exchange authorization codes for access tokens
	MasterURL string `json:"masterURL"`

	// MasterPublicURL is used for building valid client redirect URLs for internal and external access
	MasterPublicURL string `json:"masterPublicURL"`

	// AssetPublicURL is used for building valid client redirect URLs for external access
	AssetPublicURL string `json:"assetPublicURL"`

	// AlwaysShowProviderSelection will force the provider selection page to render even when there is only a single provider.
	AlwaysShowProviderSelection bool `json:"alwaysShowProviderSelection"`

	//IdentityProviders is an ordered list of ways for a user to identify themselves
	IdentityProviders []IdentityProvider `json:"identityProviders"`

	// GrantConfig describes how to handle grants
	GrantConfig GrantConfig `json:"grantConfig"`

	// SessionConfig hold information about configuring sessions.
	SessionConfig *SessionConfig `json:"sessionConfig"`

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

// SessionConfig specifies options for cookie-based sessions. Used by AuthRequestHandlerSession
type SessionConfig struct {
	// SessionSecretsFile is a reference to a file containing a serialized SessionSecrets object
	// If no file is specified, a random signing and encryption key are generated at each server start
	SessionSecretsFile string `json:"sessionSecretsFile"`
	// SessionMaxAgeSeconds specifies how long created sessions last. Used by AuthRequestHandlerSession
	SessionMaxAgeSeconds int32 `json:"sessionMaxAgeSeconds"`
	// SessionName is the cookie name used to store the session
	SessionName string `json:"sessionName"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SessionSecrets list the secrets to use to sign/encrypt and authenticate/decrypt created sessions.
type SessionSecrets struct {
	metav1.TypeMeta `json:",inline"`

	// Secrets is a list of secrets
	// New sessions are signed and encrypted using the first secret.
	// Existing sessions are decrypted/authenticated by each secret until one succeeds. This allows rotating secrets.
	Secrets []SessionSecret `json:"secrets"`
}

// SessionSecret is a secret used to authenticate/decrypt cookie-based sessions
type SessionSecret struct {
	// Authentication is used to authenticate sessions using HMAC. Recommended to use a secret with 32 or 64 bytes.
	Authentication string `json:"authentication"`
	// Encryption is used to encrypt sessions. Must be 16, 24, or 32 characters long, to select AES-128, AES-
	Encryption string `json:"encryption"`
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

	// File is a reference to your htpasswd file
	File string `json:"file"`
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
	// UseKeystoneIdentity flag indicates that user should be authenticated by keystone ID, not by username
	UseKeystoneIdentity bool `json:"useKeystoneIdentity"`
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
	// Legacy determines if OAuth2 or OIDC should be used
	// If true, OAuth2 is used
	// If false, OIDC is used
	// If nil and the URL's host is gitlab.com, OIDC is used
	// Otherwise, OAuth2 is used
	// In a future release, nil will default to using OIDC
	// Eventually this flag will be removed and only OIDC will be used
	Legacy *bool `json:"legacy,omitempty"`
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

// OpenIDClaims contains a list of OpenID claims to use when authenticating with an OpenID identity provider
type OpenIDClaims struct {
	// ID is the list of claims whose values should be used as the user ID. Required.
	// OpenID standard identity claim is "sub"
	ID []string `json:"id"`
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

// GrantConfig holds the necessary configuration options for grant handlers
type GrantConfig struct {
	// Method determines the default strategy to use when an OAuth client requests a grant.
	// This method will be used only if the specific OAuth client doesn't provide a strategy
	// of their own. Valid grant handling methods are:
	//  - auto:   always approves grant requests, useful for trusted clients
	//  - prompt: prompts the end user for approval of grant requests, useful for third-party clients
	//  - deny:   always denies grant requests, useful for black-listed clients
	Method GrantHandlerType `json:"method"`

	// ServiceAccountMethod is used for determining client authorization for service account oauth client.
	// It must be either: deny, prompt
	ServiceAccountMethod GrantHandlerType `json:"serviceAccountMethod"`
}

type GrantHandlerType string

const (
	// GrantHandlerAuto auto-approves client authorization grant requests
	GrantHandlerAuto GrantHandlerType = "auto"
	// GrantHandlerPrompt prompts the user to approve new client authorization grant requests
	GrantHandlerPrompt GrantHandlerType = "prompt"
	// GrantHandlerDeny auto-denies client authorization grant requests
	GrantHandlerDeny GrantHandlerType = "deny"
)
...
// LDAPSyncConfig holds the necessary configuration options to define an LDAP group sync
type LDAPSyncConfig struct {
	metav1.TypeMeta `json:",inline"`
	// Host is the scheme, host and port of the LDAP server to connect to:
	// scheme://host:port
	URL string `json:"url"`
	// BindDN is an optional DN to bind to the LDAP server with
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

	// LDAPGroupUIDToOpenShiftGroupNameMapping is an optional direct mapping of LDAP group UIDs to
	// OpenShift Group names
	LDAPGroupUIDToOpenShiftGroupNameMapping map[string]string `json:"groupUIDNameMapping"`

	// RFC2307Config holds the configuration for extracting data from an LDAP server set up in a fashion
	// similar to RFC2307: first-class group and user entries, with group membership determined by a
	// multi-valued attribute on the group entry listing its members
	RFC2307Config *RFC2307Config `json:"rfc2307,omitempty"`

	// ActiveDirectoryConfig holds the configuration for extracting data from an LDAP server set up in a
	// fashion similar to that used in Active Directory: first-class user entries, with group membership
	// determined by a multi-valued attribute on members listing groups they are a member of
	ActiveDirectoryConfig *ActiveDirectoryConfig `json:"activeDirectory,omitempty"`

	// AugmentedActiveDirectoryConfig holds the configuration for extracting data from an LDAP server
	// set up in a fashion similar to that used in Active Directory as described above, with one addition:
	// first-class group entries exist and are used to hold metadata but not group membership
	AugmentedActiveDirectoryConfig *AugmentedActiveDirectoryConfig `json:"augmentedActiveDirectory,omitempty"`
}

// RFC2307Config holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the RFC2307 schema
type RFC2307Config struct {
	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP group entry will be interpreted  as its members.
	// The values contained in those attributes must be queryable by your UserUIDAttribute
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`

	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserUIDAttribute defines which attribute on an LDAP user entry will be interpreted as its unique identifier.
	// It must correspond to values that will be found from the GroupMembershipAttributes
	UserUIDAttribute string `json:"userUIDAttribute"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be used, in order, as its OpenShift user name.
	// The first attribute with a non-empty value is used. This should match your PreferredUsername setting for your LDAPPasswordIdentityProvider
	UserNameAttributes []string `json:"userNameAttributes"`

	// TolerateMemberNotFoundErrors determines the behavior of the LDAP sync job when missing user entries are
	// encountered. If 'true', an LDAP query for users that doesn't find any will be tolerated and an only
	// and error will be logged. If 'false', the LDAP sync job will fail if a query for users doesn't find
	// any. The default value is 'false'. Misconfigured LDAP sync jobs with this flag set to 'true' can cause
	// group membership to be removed, so it is recommended to use this flag with caution.
	TolerateMemberNotFoundErrors bool `json:"tolerateMemberNotFoundErrors"`

	// TolerateMemberOutOfScopeErrors determines the behavior of the LDAP sync job when out-of-scope user entries
	// are encountered. If 'true', an LDAP query for a user that falls outside of the base DN given for the all
	// user query will be tolerated and only an error will be logged. If 'false', the LDAP sync job will fail
	// if a user query would search outside of the base DN specified by the all user query. Misconfigured LDAP
	// sync jobs with this flag set to 'true' can result in groups missing users, so it is recommended to use
	// this flag with caution.
	TolerateMemberOutOfScopeErrors bool `json:"tolerateMemberOutOfScopeErrors"`
}

// ActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the Active Directory schema
type ActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`
}

// AugmentedActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the augmented Active Directory schema
type AugmentedActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`

	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes"`
}

// LDAPQuery holds the options necessary to build an LDAP query
type LDAPQuery struct {
	// The DN of the branch of the directory where all searches should start from
	BaseDN string `json:"baseDN"`

	// The (optional) scope of the search. Can be:
	// base: only the base object,
	// one:  all object on the base level,
	// sub:  the entire subtree
	// Defaults to the entire subtree if not set
	Scope string `json:"scope"`

	// The (optional) behavior of the search with regards to alisases. Can be:
	// never:  never dereference aliases,
	// search: only dereference in searching,
	// base:   only dereference in finding the base object,
	// always: always dereference
	// Defaults to always dereferencing if not set
	DerefAliases string `json:"derefAliases"`

	// TimeLimit holds the limit of time in seconds that any request to the server can remain outstanding
	// before the wait for a response is given up. If this is 0, no client-side limit is imposed
	TimeLimit int `json:"timeout"`

	// Filter is a valid LDAP search filter that retrieves all relevant entries from the LDAP server with the base DN
	Filter string `json:"filter"`

	// PageSize is the maximum preferred page size, measured in LDAP entries. A page size of 0 means no paging will be done.
	PageSize int `json:"pageSize"`
}
...
```
