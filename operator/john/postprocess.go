package john

import (
	"encoding/json"
	"fmt"

	yaml2 "gopkg.in/yaml.v2" // nolint: depguard // needed for weird tricks
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"

	"istio.io/istio/operator/pkg/tpath"
	"istio.io/istio/operator/pkg/util"
)

func postProcess(comp Component, spec ComponentSpec, manifests []Manifest) ([]Manifest, error) {
	if spec.Kubernetes == nil {
		return manifests, nil
	}
	type Patch struct {
		Kind, Name string
		Patch      string
	}
	rn := comp.ResourceName
	if spec.Name != "" {
		// Gateways can override the name
		rn = spec.Name
	}
	if comp.Name == "pilot" {
		// TODO: if revision and istiod += -revision
	}
	rt := comp.ResourceType
	patches := map[string]Patch{
		"affinity":            {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"spec":{"affinity":%s}}}}`},
		"env":                 {Kind: rt, Name: rn, Patch: fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q, "env": %%s}]}}}}`, comp.ContainerName)},
		"hpaSpec":             {Kind: "HorizontalPodAutoscaler", Name: rn, Patch: `{"spec":%s}`},
		"imagePullPolicy":     {Kind: rt, Name: rn, Patch: fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q, "imagePullPolicy": %%s}]}}}}`, comp.ContainerName)},
		"nodeSelector":        {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"spec":{"nodeSelector":%s}}}}`},
		"podDisruptionBudget": {Kind: "PodDisruptionBudget", Name: rn, Patch: `{"spec":%s}`},
		"podAnnotations":      {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"metadata":{"annotations":%s}}}}`},
		"priorityClassName":   {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"spec":{"priorityClassName":%s}}}}`},
		"readinessProbe":      {Kind: rt, Name: rn, Patch: fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q, "readinessProbe": %%s}]}}}}`, comp.ContainerName)},
		"replicaCount":        {Kind: rt, Name: rn, Patch: `{"spec":{"replicas":%s}}`},
		"resources":           {Kind: rt, Name: rn, Patch: fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q, "resources": %%s}]}}}}`, comp.ContainerName)},
		"strategy":            {Kind: rt, Name: rn, Patch: `{"spec":{"strategy":%s}}`},
		"tolerations":         {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"spec":{"tolerations":%s}}}}`},
		"serviceAnnotations":  {Kind: "Service", Name: rn, Patch: `{"metadata":{"annotations":%s}}`},
		"service":             {Kind: "Service", Name: rn, Patch: `{"spec":%s}`},
		"securityContext":     {Kind: rt, Name: rn, Patch: `{"spec":{"template":{"spec":{"securityContext":%s}}}}`},
	}
	needPatching := map[int][]string{}
	for field, k := range patches {
		v, ok := spec.Raw.GetPath("k8s." + field)
		if !ok {
			continue
		}
		inner, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		patch := fmt.Sprintf(k.Patch, inner)
		// Find which manifests need the patch
		for idx, m := range manifests {
			if k.Kind == m.GetKind() && k.Name == m.GetName() {
				needPatching[idx] = append(needPatching[idx], patch)
			}
		}
	}

	for idx, patches := range needPatching {
		m := manifests[idx]
		baseJSON, err := yaml.YAMLToJSON([]byte(m.Content))
		if err != nil {
			return nil, err
		}
		typed, err := scheme.Scheme.New(m.GroupVersionKind())
		if err != nil {
			return nil, err
		}

		for _, patch := range patches {
			newBytes, err := strategicpatch.StrategicMergePatch(baseJSON, []byte(patch), typed)
			if err != nil {
				return nil, fmt.Errorf("patch: %v", err)
			}
			baseJSON = newBytes
		}
		us := &unstructured.Unstructured{}
		if err := json.Unmarshal(baseJSON, us); err != nil {
			return nil, err
		}
		yml, err := yaml.Marshal(us)
		if err != nil {
			return nil, err
		}
		// Rebuild our manifest
		manifests[idx] = Manifest{
			Unstructured: us,
			Content:      string(yml),
		}
	}

	for _, o := range spec.Kubernetes.Overlays {
		for idx, m := range manifests {
			if o.Kind != m.GetKind() {
				continue
			}
			// While patches have ApiVersion, this is ignored for legacy compatibility
			if o.Name != m.GetName() {
				continue
			}
			mfs, err := applyPatches(m, o.Patches)
			if err != nil {
				return nil, err
			}
			manifests[idx] = mfs
			//for _,p := range o.Patches {
			//	patch := MakePatch(p.Value, p.Path)
			//	needPatching[idx] = append(needPatching[idx], patch)
			//}
		}
	}

	return manifests, nil
}

// applyPatches applies the given patches against the given object. It returns the resulting patched YAML if successful,
// or a list of errors otherwise.
func applyPatches(base Manifest, patches []Patch) (Manifest, error) {
	bo := make(map[any]any)
	// Use yaml2 specifically to allow interface{} as key which WritePathContext treats specially
	err := yaml2.Unmarshal([]byte(base.Content), &bo)
	if err != nil {
		return Manifest{}, err
	}
	var errs util.Errors
	for _, p := range patches {
		v := p.Value
		inc, _, err := tpath.GetPathContext(bo, util.PathFromString(p.Path), true)
		if err != nil {
			errs = util.AppendErr(errs, err)
			continue
		}

		err = tpath.WritePathContext(inc, v, false)
		if err != nil {
			errs = util.AppendErr(errs, err)
		}
	}
	oy, err := yaml2.Marshal(bo)
	if err != nil {
		return Manifest{}, util.AppendErr(errs, err).ToError()
	}

	// Rebuild our manifest
	us := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(oy, us); err != nil {
		return Manifest{}, err
	}
	return Manifest{
		Unstructured: us,
		Content:      string(oy),
	}, nil
}
