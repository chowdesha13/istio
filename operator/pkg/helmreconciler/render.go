// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helmreconciler

import (
	"context"
	"fmt"
	"strings"
	"sync"

	jsonpatch "github.com/evanphx/json-patch"
	"helm.sh/helm/v3/pkg/releaseutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	util2 "k8s.io/kubectl/pkg/util"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"istio.io/api/operator/v1alpha1"
	"istio.io/pkg/log"
	pkgversion "istio.io/pkg/version"

	"istio.io/istio/operator/pkg/apis/istio"
	valuesv1alpha1 "istio.io/istio/operator/pkg/apis/istio/v1alpha1"
	"istio.io/istio/operator/pkg/controlplane"
	"istio.io/istio/operator/pkg/helm"
	omanifest "istio.io/istio/operator/pkg/manifest"
	"istio.io/istio/operator/pkg/name"
	"istio.io/istio/operator/pkg/object"
	"istio.io/istio/operator/pkg/tpath"
	"istio.io/istio/operator/pkg/translate"
	"istio.io/istio/operator/pkg/util"
	"istio.io/istio/operator/pkg/validate"
	binversion "istio.io/istio/operator/version"
	"istio.io/istio/pilot/pkg/model"
)

// ObjectCache is a cache of objects.
type ObjectCache struct {
	// cache is a cache keyed by object Hash() function.
	cache map[string]*object.K8sObject
	mu    *sync.RWMutex
}

const (
	// owningResourceKey represents the name of the owner to which the resource relates
	owningResourceKey = MetadataNamespace + "/owning-resource"
	// operatorLabelStr indicates Istio operator is managing this resource.
	operatorLabelStr = name.OperatorAPINamespace + "/managed"
	// operatorReconcileStr indicates that the operator will reconcile the resource.
	operatorReconcileStr = "Reconcile"
	// istioComponentLabelStr indicates which Istio component a resource belongs to.
	istioComponentLabelStr = name.OperatorAPINamespace + "/component"
	// istioVersionLabelStr indicates the Istio version of the installation.
	istioVersionLabelStr = name.OperatorAPINamespace + "/version"
)

var (
	// objectCaches holds the latest copy of each object applied by the controller, keyed by the IstioOperator CR name
	// and the object Hash() function.
	objectCaches   = make(map[string]*ObjectCache)
	objectCachesMu sync.RWMutex

	scope = log.RegisterScope("installer", "installer", 0)
)

// FlushObjectCaches flushes all K8s object caches.
func FlushObjectCaches() {
	objectCachesMu.Lock()
	defer objectCachesMu.Unlock()
	objectCaches = make(map[string]*ObjectCache)
}

func (h *HelmReconciler) RenderCharts() (ChartManifestsMap, error) {
	iopSpec := h.iop.Spec
	if err := validate.CheckIstioOperatorSpec(iopSpec, false); err != nil {
		return nil, err
	}

	t, err := translate.NewTranslator(binversion.OperatorBinaryVersion.MinorVersion)
	if err != nil {
		return nil, err
	}

	cp, err := controlplane.NewIstioOperator(iopSpec, t)
	if err != nil {
		return nil, err
	}
	if err := cp.Run(); err != nil {
		return nil, fmt.Errorf("failed to create Istio control plane with spec: \n%v\nerror: %s", iopSpec, err)
	}

	manifests, errs := cp.RenderManifest()
	if errs != nil {
		err = errs.ToError()
	}

	h.manifests = manifests

	return toChartManifestsMap(manifests), err
}

func (h *HelmReconciler) GetManifests() name.ManifestMap {
	return h.manifests
}

// MergeIOPSWithProfile overlays the values in iop on top of the defaults for the profile given by iop.profile and
// returns the merged result.
func MergeIOPSWithProfile(iop *valuesv1alpha1.IstioOperator) (*v1alpha1.IstioOperatorSpec, error) {
	profileYAML, err := helm.GetProfileYAML(iop.Spec.InstallPackagePath, iop.Spec.Profile)
	if err != nil {
		return nil, err
	}

	// Due to the fact that base profile is compiled in before a tag can be created, we must allow an additional
	// override from variables that are set during release build time.
	hub := pkgversion.DockerInfo.Hub
	tag := pkgversion.DockerInfo.Tag
	if hub != "" && hub != "unknown" && tag != "" && tag != "unknown" {
		buildHubTagOverlayYAML, err := helm.GenerateHubTagOverlay(hub, tag)
		if err != nil {
			return nil, err
		}
		profileYAML, err = util.OverlayYAML(profileYAML, buildHubTagOverlayYAML)
		if err != nil {
			return nil, err
		}
	}

	overlayYAML, err := util.MarshalWithJSONPB(iop)
	if err != nil {
		return nil, err
	}
	mvs := binversion.OperatorBinaryVersion.MinorVersion
	t, err := translate.NewReverseTranslator(mvs)
	if err != nil {
		return nil, fmt.Errorf("error creating values.yaml translator: %s", err)
	}
	overlayYAML, err = t.TranslateK8SfromValueToIOP(overlayYAML)
	if err != nil {
		return nil, fmt.Errorf("could not overlay k8s settings from values to IOP: %s", err)
	}

	mergedYAML, err := util.OverlayYAML(profileYAML, overlayYAML)
	if err != nil {
		return nil, err
	}

	mergedYAML, err = translate.OverlayValuesEnablement(mergedYAML, overlayYAML, "")
	if err != nil {
		return nil, err
	}

	mergedYAMLSpec, err := tpath.GetSpecSubtree(mergedYAML)
	if err != nil {
		return nil, err
	}

	return istio.UnmarshalAndValidateIOPS(mergedYAMLSpec)
}

// ProcessManifest apply the manifest to create or update resources, returns the number of objects processed
func (h *HelmReconciler) ProcessManifest(manifests []releaseutil.Manifest, hasDependencies bool) (object.K8sObjects, error) {
	var processedObjects object.K8sObjects
	for _, manifest := range manifests {
		var errs util.Errors
		objAccessor, err := meta.Accessor(h.iop)
		if err != nil {
			return nil, err
		}
		crName := objAccessor.GetName()
		owningResource := crName + "-" + manifest.Name
		scope.Infof("Processing resources from manifest: %s for CR %s", manifest.Name, crName)
		allObjects, err := object.ParseK8sObjectsFromYAMLManifest(manifest.Content)
		if err != nil {
			return nil, err
		}

		objectCachesMu.Lock()

		// Create and/or get the cache corresponding to the CR crName we're processing. Per crName partitioning is required to
		// prune the cache to remove any objects not in the manifest generated for a given CR.
		if objectCaches[owningResource] == nil {
			objectCaches[owningResource] = &ObjectCache{
				cache: make(map[string]*object.K8sObject),
				mu:    &sync.RWMutex{},
			}
		}
		objectCache := objectCaches[owningResource]

		objectCachesMu.Unlock()

		// Ensure that for a given CR crName only one control loop uses the per-crName cache at any time.
		objectCache.mu.Lock()
		defer objectCache.mu.Unlock()

		// No further locking required beyond this point, since we have a ptr to a cache corresponding to a CR crName and no
		// other controller is allowed to work on at the same time.
		var deployedObjects int
		var changedObjects object.K8sObjects
		var changedObjectKeys []string
		allObjectsMap := make(map[string]bool)

		// Check which objects in the manifest have changed from those in the cache.
		for _, obj := range allObjects {
			oh := obj.Hash()
			allObjectsMap[oh] = true
			if co, ok := objectCache.cache[oh]; ok && obj.Equal(co) {
				// Object is in the cache and unchanged.
				deployedObjects++
				continue
			}
			changedObjects = append(changedObjects, obj)
			changedObjectKeys = append(changedObjectKeys, oh)
		}

		var plog *util.ManifestLog
		if len(changedObjectKeys) > 0 {
			plog = h.opts.ProgressLog.NewComponent(manifest.Name)
			scope.Infof("The following objects differ between generated manifest and cache: \n - %s", strings.Join(changedObjectKeys, "\n - "))
		} else {
			scope.Infof("Generated manifest objects are the same as cached for component %s.", manifest.Name)
		}

		// For each changed object, write it to the API server.
		for _, obj := range changedObjects {
			obju := obj.UnstructuredObject()
			if err := applyLabelsAndAnnotations(obju, manifest.Name, h.iop.Spec.Revision, owningResource, crName); err != nil {
				return nil, err
			}
			if err := h.ProcessObject(manifest.Name, obj.UnstructuredObject()); err != nil {
				scope.Error(err.Error())
				errs = util.AppendErr(errs, fmt.Errorf("processing manifest %s: %w", manifest.Name, err))
				continue
			}
			plog.ReportProgress()
			processedObjects = append(processedObjects, obj)
			// Update the cache with the latest object.
			objectCache.cache[obj.Hash()] = obj
		}

		// Prune anything not in the manifest out of the cache.
		var removeKeys []string
		for k := range objectCache.cache {
			if !allObjectsMap[k] {
				removeKeys = append(removeKeys, k)
			}
		}
		for _, k := range removeKeys {
			scope.Infof("Pruning object %s from cache.", k)
			delete(objectCache.cache, k)
		}

		if len(changedObjectKeys) > 0 {
			if len(errs) != 0 {
				plog.ReportError(util.ToString(errs.Dedup(), "\n"))
				return processedObjects, errs.ToError()
			}

			// If we are depending on a component, we may depend on it actually running (eg Deployment is ready)
			// For example, for the validation webhook to become ready, so we should wait for it always.
			if hasDependencies || h.opts.Wait {
				err := omanifest.WaitForResources(processedObjects, h.clientSet,
					internalDepTimeout, h.opts.DryRun, plog)
				if err != nil {
					werr := fmt.Errorf("failed to wait for resource: %v", err)
					plog.ReportError(werr.Error())
					return processedObjects, werr
				}
				plog.ReportFinished()
			} else {
				plog.ReportFinished()
			}
		}
	}
	return processedObjects, nil
}

// applyLabelsAndAnnotations applies owner labels and annotations to the object.
func applyLabelsAndAnnotations(obj runtime.Object, componentName, revision, owningResource, crName string) error {
	labels := make(map[string]string)

	componentLabelValue := componentName
	// Only pilot component uses revisions
	if componentName == string(name.PilotComponentName) {
		if revision == "" {
			revision = "default"
		}
		labels[model.RevisionLabel] = revision
		componentLabelValue += "-" + revision
	}

	labels[operatorLabelStr] = operatorReconcileStr
	labels[owningResourceKey] = owningResource
	labels[istioComponentLabelStr] = componentLabelValue
	labels[istioVersionLabelStr] = pkgversion.Info.Version

	// add owner labels
	labels[OwnerNameKey] = crName
	labels[OwnerGroupKey] = valuesv1alpha1.IstioOperatorGVK.Group
	labels[OwnerKindKey] = valuesv1alpha1.IstioOperatorGVK.Kind

	for k, v := range labels {
		err := util.SetLabel(obj, k, v)
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcessObject creates or updates an object in the API server depending on whether it already exists.
// It mutates obj.
func (h *HelmReconciler) ProcessObject(chartName string, obj *unstructured.Unstructured) error {
	if obj.GetKind() == "List" {
		allErrors := []error{}
		list, err := obj.ToList()
		if err != nil {
			scope.Errorf("error converting List object: %s", err)
			return err
		}
		for _, item := range list.Items {
			err = h.ProcessObject(chartName, &item)
			if err != nil {
				allErrors = append(allErrors, err)
			}
		}
		return utilerrors.NewAggregate(allErrors)
	}

	if err := util2.CreateApplyAnnotation(obj, unstructured.UnstructuredJSONScheme); err != nil {
		scope.Errorf("unexpected error adding apply annotation to object: %s", err)
	}

	receiver := &unstructured.Unstructured{}
	receiver.SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
	objectKey, _ := client.ObjectKeyFromObject(obj)
	objectStr := fmt.Sprintf("%s/%s/%s", obj.GetKind(), obj.GetNamespace(), obj.GetName())

	scope.Debugf("Processing object:\n%s\n\n", util.ToYAML(obj))
	if h.opts.DryRun {
		scope.Infof("Not applying object %s because of dry run.", objectStr)
		return nil
	}

	err := h.client.Get(context.TODO(), objectKey, receiver)
	switch {
	case apierrors.IsNotFound(err):
		scope.Infof("creating resource: %s", objectStr)
		err = h.client.Create(context.TODO(), obj)
		if err != nil {
			return fmt.Errorf("failed to create %q: %w", objectStr, err)
		}
		return nil
	case err == nil:
		scope.Infof("updating resource: %s", objectStr)
		if err := applyOverlay(receiver, obj); err != nil {
			return err
		}
		return h.client.Update(context.TODO(), receiver)
	}
	return err
}

// applyOverlay applies an overlay using JSON patch strategy over the current Object in place.
func applyOverlay(current, overlay runtime.Object) error {
	cj, err := runtime.Encode(unstructured.UnstructuredJSONScheme, current)
	if err != nil {
		return err
	}
	uj, err := runtime.Encode(unstructured.UnstructuredJSONScheme, overlay)
	if err != nil {
		return err
	}
	merged, err := jsonpatch.MergePatch(cj, uj)
	if err != nil {
		return err
	}
	return runtime.DecodeInto(unstructured.UnstructuredJSONScheme, merged, current)
}

func toChartManifestsMap(m name.ManifestMap) ChartManifestsMap {
	out := make(ChartManifestsMap)
	for k, v := range m {
		out[string(k)] = []releaseutil.Manifest{{
			Name:    string(k),
			Content: strings.Join(v, helm.YAMLSeparator),
		}}
	}
	return out
}
