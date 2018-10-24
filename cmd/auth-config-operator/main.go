package main

import (
	"context"
	"flag"
	"runtime"
	"time"

	stub "github.com/openshift/auth-config-operator/pkg/stub"
	sdk "github.com/operator-framework/operator-sdk/pkg/sdk"
	k8sutil "github.com/operator-framework/operator-sdk/pkg/util/k8sutil"
	sdkVersion "github.com/operator-framework/operator-sdk/version"

	"github.com/golang/glog"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func init() {
	flag.Parse()
}
func printVersion() {
	glog.Infof("Go Version: %s", runtime.Version())
	glog.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	glog.Infof("operator-sdk Version: %v", sdkVersion.Version)
}

func main() {
	printVersion()

	sdk.ExposeMetricsPort()

	resource := "auth.config.openshift.io/v1alpha1"
	kind := "ClusterAuthentication"
	namespace, err := k8sutil.GetWatchNamespace()
	if err != nil {
		glog.Fatalf("failed to get watch namespace: %v", err)
	}
	resyncPeriod := 5
	glog.Infof("Watching %s, %s, %s, %d", resource, kind, namespace, resyncPeriod)
	sdk.Watch(resource, kind, namespace, time.Duration(resyncPeriod)*time.Second)
	handler, err := stub.NewHandler()
	if err != nil {
		glog.Fatalf("failed to initialize client: %v", err)
	}
	sdk.Handle(handler)
	sdk.Run(context.TODO())
}
