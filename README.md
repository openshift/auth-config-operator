OpenShift OAuth Operator
========================

This operator is responsible for managing user authentication configuration and
the internal oauth server. The components managed by this operator include:

* Enabling the built-in oauth server
* Configuring the built-in oauth server
* Updating the metadata served over the well-known endpoint
* Configuring IDP integrations
* Setting up token review endpoints
* Keycloak integration

While the oauth server is built into the kube api server, this operator will not
directly manage any binaries but will provide configuration to the kube api
server components. When the oauth server is pulled out into a separate
component, this operator will be responsible for managing its lifecycle.

### Goals
* OAuth server can be configured after cluster installation
* Configuring oauth requires no direct access to kube-api-server

### Non-Goals
* Removing the oauth server from the kube api server


### Dependencies
* Kube API server, with OpenShift OAuth server patch, and the operator that
  manages it, the cluster-kube-apiserver-operator
  * There are configuration values and information that must flow:
    * From kube api operator to oauth-operator, e.g. master url
    * From oauth-operator to kube api operator, e.g. oauth config
  * And some configuration that stays private to the oauth-operator
  * A deeper examination of the specific config values in each category is
    discussed further below.
* For advanced use cases, KeyCloak must be set up either manually or via an
  operator of its own
