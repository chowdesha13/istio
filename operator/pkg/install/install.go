package install

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/operator/pkg/component"
	"istio.io/istio/operator/pkg/manifest"
	"istio.io/istio/operator/pkg/util"
	"istio.io/istio/operator/pkg/util/clog"
	"istio.io/istio/operator/pkg/util/progress"
	"istio.io/istio/operator/pkg/values"
	"istio.io/istio/operator/pkg/webhook"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/istiomultierror"
	"istio.io/istio/pkg/util/sets"
)

type Installer struct {
	Force          bool
	DryRun         bool
	SkipWait       bool
	Kube           kube.CLIClient
	WaitTimeout    time.Duration
	Logger         clog.Logger
	ProgressLogger *progress.Log
}

// InstallManifests applies a set of rendered manifests to the cluster.
func (i Installer) InstallManifests(manifests []manifest.ManifestSet, vals values.Map) error {
	err := i.installSystemNamespace(vals)
	if err != nil {
		return err
	}

	if err := webhook.CheckWebhooks(manifests, vals, i.Kube); err != nil {
		if i.Force {
			i.Logger.LogAndErrorf("invalid webhook configs; continuing because of --force: %v", err)
		} else {
			return err
		}
	}

	if err := i.install(manifests); err != nil {
		return err
	}

	i.ProgressLogger.SetState(progress.StateComplete)
	return nil
}

func (i Installer) installSystemNamespace(vals values.Map) error {
	ns := ptr.NonEmptyOrDefault(values.TryGetPathAs[string](vals, "metadata.namespace"), "istio-system")
	network := values.TryGetPathAs[string](vals, "spec.values.global.network")
	if err := util.CreateNamespace(i.Kube.Kube(), ns, network, i.DryRun); err != nil {
		return err
	}
	return nil
}

func (i Installer) install(manifests []manifest.ManifestSet) error {
	var mu sync.Mutex
	errors := istiomultierror.New()
	// wg waits for all manifest processing goroutines to finish
	var wg sync.WaitGroup

	disabledComponents := sets.New(slices.Map(component.AllComponents, func(e component.Component) component.Name {
		return e.Name
	})...)
	dependencyWaitCh := dependenciesChannels()
	for _, manifest := range manifests {
		c := manifest.Component
		ms := manifest.Manifests
		disabledComponents.Delete(c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s := dependencyWaitCh[c]; s != nil {
				<-s
			}

			if len(ms) != 0 {
				if err := i.applyManifestSet(manifest); err != nil {
					mu.Lock()
					errors = multierror.Append(errors, err)
					mu.Unlock()
				}
			}

			// Signal all the components that depend on us.
			for _, ch := range componentDependencies[c] {
				dependencyWaitCh[ch] <- struct{}{}
			}
		}()
	}
	// For any components we did not install, mark them as "done"
	for c := range disabledComponents {
		// Signal all the components that depend on us.
		for _, ch := range componentDependencies[c] {
			dependencyWaitCh[ch] <- struct{}{}
		}
	}
	wg.Wait()
	return errors.ErrorOrNil()
}

func (i Installer) applyManifestSet(manifestSet manifest.ManifestSet) error {
	cname := string(manifestSet.Component)

	manifests := manifestSet.Manifests

	plog := i.ProgressLogger.NewComponent(cname)

	// TODO
	// allObjects.Sort(object.DefaultObjectOrder())
	for _, obj := range manifests {
		//if err := h.applyLabelsAndAnnotations(obju, cname); err != nil {
		//	return err
		//}
		if err := i.serverSideApply(obj); err != nil {
			plog.ReportError(err.Error())
			return err
		}
		plog.ReportProgress()
	}

	if !i.SkipWait {
		if err := WaitForResources(manifests, i.Kube, i.WaitTimeout, i.DryRun, plog); err != nil {
			werr := fmt.Errorf("failed to wait for resource: %v", err)
			plog.ReportError(werr.Error())
			return werr
		}
	}
	plog.ReportFinished()
	return nil
}

// serverSideApply creates or updates an object in the API server depending on whether it already exists.
func (i Installer) serverSideApply(obj manifest.Manifest) error {
	const fieldOwnerOperator = "istio-operator"
	dc, err := i.Kube.DynamicClientFor(obj.GroupVersionKind(), obj.Unstructured, "")
	if err != nil {
		return err
	}
	objectStr := fmt.Sprintf("%s/%s/%s", obj.GetKind(), obj.GetNamespace(), obj.GetName())
	var dryRun []string
	// TODO: can we do this? it doesn't work well if the namespace is not already created
	if i.DryRun {
		return nil
		//	dryRun = []string{metav1.DryRunAll}
	}
	if _, err := dc.Patch(context.TODO(), obj.GetName(), types.ApplyPatchType, []byte(obj.Content), metav1.PatchOptions{
		DryRun:       dryRun,
		Force:        ptr.Of(true),
		FieldManager: fieldOwnerOperator,
	}); err != nil {
		return fmt.Errorf("failed to update resource with server-side apply for obj %v: %v", objectStr, err)
	}
	return nil
}

var componentDependencies = map[component.Name][]component.Name{
	component.PilotComponentName: {
		component.CNIComponentName,
		component.IngressComponentName,
		component.EgressComponentName,
	},
	component.BaseComponentName: {
		component.PilotComponentName,
	},
	component.CNIComponentName: {
		component.ZtunnelComponentName,
	},
}

func dependenciesChannels() map[component.Name]chan struct{} {
	ret := make(map[component.Name]chan struct{})
	for _, parent := range componentDependencies {
		for _, child := range parent {
			ret[child] = make(chan struct{}, 1)
		}
	}
	return ret
}
