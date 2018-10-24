package stub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/openshift/auth-config-operator/pkg/apis/auth/v1alpha1"

	"github.com/golang/glog"
	kubeapiserverconfigclientv1alpha1 "github.com/openshift/cluster-kube-apiserver-operator/pkg/generated/clientset/versioned/typed/kubeapiserver/v1alpha1"
	"github.com/operator-framework/operator-sdk/pkg/k8sclient"
	"github.com/operator-framework/operator-sdk/pkg/sdk"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	ClusterAuthResourceNameDefault         = "instance"
	KubeApiserverOperatorConfigNameDefault = "instance"
)

func NewHandler() (sdk.Handler, error) {
	kclient, err := kubeapiserverconfigclientv1alpha1.NewForConfig(k8sclient.GetKubeConfig())
	if err != nil {
		return nil, err
	}
	return &Handler{
		ClusterAuthResourceName:         ClusterAuthResourceNameDefault,
		KubeApiserverOperatorConfigName: KubeApiserverOperatorConfigNameDefault,
		KubeapiserverConfigClient:       kclient,
	}, nil
}

type Handler struct {
	ClusterAuthResourceName         string
	KubeApiserverOperatorConfigName string

	KubeapiserverConfigClient kubeapiserverconfigclientv1alpha1.KubeapiserverV1alpha1Interface
}

func (h *Handler) Handle(ctx context.Context, event sdk.Event) error {
	switch o := event.Object.(type) {
	case *v1alpha1.ClusterAuthentication:
		if err := h.sync(o); err != nil {
			glog.Errorf("error syncing clusterauth: %v", err)
			return err
		}
	}
	return nil
}

func (h *Handler) sync(ca *v1alpha1.ClusterAuthentication) error {
	if ca == nil {
		return errors.New("unknown ClusterAuthentication resource: nil")
	}
	if ca.GetName() != h.ClusterAuthResourceName {
		glog.Warningf("unknown ClusterAuthentication resource: name='%s'", ca.GetName())
		return nil
	}
	glog.Infof("syncing clusterauth: %s", ca.GetName())
	kconfig, err := h.KubeapiserverConfigClient.KubeApiserverOperatorConfigs().
		Get(h.KubeApiserverOperatorConfigName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	userConfig := v1alpha1.ClusterAuthenticationSpec{}
	json.NewDecoder(bytes.NewBuffer(kconfig.Spec.UserConfig.Raw)).Decode(&userConfig)
	if reflect.DeepEqual(ca.Spec, userConfig) {
		return nil
	}
	raw, err := json.Marshal(ca.Spec)
	if err != nil {
		return err
	}
	kconfig.Spec.UserConfig = runtime.RawExtension{Raw: raw}
	_, err = h.KubeapiserverConfigClient.KubeApiserverOperatorConfigs().Update(kconfig)
	return err
}
