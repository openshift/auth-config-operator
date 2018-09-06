package stub

import (
	"context"
	"fmt"

	"github.com/openshift/auth-config-operator/pkg/apis/auth/v1alpha1"

	"github.com/operator-framework/operator-sdk/pkg/sdk"
)

func NewHandler() sdk.Handler {
	return &Handler{}
}

type Handler struct {
	// Fill me
}

func (h *Handler) Handle(ctx context.Context, event sdk.Event) error {
	switch o := event.Object.(type) {
	case *v1alpha1.ClusterAuthentication:
		fmt.Printf("Got ClusterAuthentication resource: %#v\n", o)
		return nil
	}
	return nil
}
