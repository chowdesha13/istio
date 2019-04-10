// Code generated by go-bindata.
// sources:
// testdata/authentication-v1alpha1-Policy-invalid.yaml
// testdata/authentication-v1alpha1-Policy-valid.yaml
// testdata/config-v1alpha2-HTTPAPISpec-invalid.yaml
// testdata/config-v1alpha2-HTTPAPISpec-valid.yaml
// testdata/config-v1alpha2-HTTPAPISpecBinding-invalid.yaml
// testdata/config-v1alpha2-HTTPAPISpecBinding-valid.yaml
// testdata/config-v1alpha2-QuotaSpec-invalid.yaml
// testdata/config-v1alpha2-QuotaSpec-valid.yaml
// testdata/config-v1alpha2-QuotaSpecBinding-invalid.yaml
// testdata/config-v1alpha2-QuotaSpecBinding-valid.yaml
// testdata/config-v1alpha2-rule-invalid.yaml
// testdata/config-v1alpha2-rule-valid.yaml
// testdata/networking-v1alpha3-DestinationRule-invalid.yaml
// testdata/networking-v1alpha3-DestinationRule-valid.yaml
// testdata/networking-v1alpha3-Gateway-invalid.yaml
// testdata/networking-v1alpha3-Gateway-valid.yaml
// testdata/networking-v1alpha3-ServiceEntry-invalid-skipped.yaml
// testdata/networking-v1alpha3-ServiceEntry-valid-skipped.yaml
// testdata/networking-v1alpha3-VirtualService-invalid.yaml
// testdata/networking-v1alpha3-VirtualService-valid.yaml
// testdata/rbac-v1alpha1-ServiceRole-invalid.yaml
// testdata/rbac-v1alpha1-ServiceRole-valid.yaml
// testdata/rbac-v1alpha1-ServiceRoleBinding-invalid.yaml
// testdata/rbac-v1alpha1-ServiceRoleBinding-valid.yaml
// DO NOT EDIT!

package validation

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _testdataAuthenticationV1alpha1PolicyInvalidYaml = []byte(`apiVersion: "authentication.istio.io/v1alpha1"
kind: "Policy"
metadata:
  name: invalid-authentication-policy
spec:
  targets:
  - name: "bad.target"
`)

func testdataAuthenticationV1alpha1PolicyInvalidYamlBytes() ([]byte, error) {
	return _testdataAuthenticationV1alpha1PolicyInvalidYaml, nil
}

func testdataAuthenticationV1alpha1PolicyInvalidYaml() (*asset, error) {
	bytes, err := testdataAuthenticationV1alpha1PolicyInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/authentication-v1alpha1-Policy-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataAuthenticationV1alpha1PolicyValidYaml = []byte(`apiVersion: "authentication.istio.io/v1alpha1"
kind: "Policy"
metadata:
  name: valid-authentication-policy
spec:
  targets:
  - name: good-target
`)

func testdataAuthenticationV1alpha1PolicyValidYamlBytes() ([]byte, error) {
	return _testdataAuthenticationV1alpha1PolicyValidYaml, nil
}

func testdataAuthenticationV1alpha1PolicyValidYaml() (*asset, error) {
	bytes, err := testdataAuthenticationV1alpha1PolicyValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/authentication-v1alpha1-Policy-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2HttpapispecInvalidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: HTTPAPISpec
metadata:
  name: invalid-http-api-spec
spec:
  apiKeys:
  - query: key
  attributes:
    attributes:
      api.service:
        stringValue: bookinfo.endpoints.istio-manlinl.cloud.goog
      api.version:
        stringValue: v1
`)

func testdataConfigV1alpha2HttpapispecInvalidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2HttpapispecInvalidYaml, nil
}

func testdataConfigV1alpha2HttpapispecInvalidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2HttpapispecInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-HTTPAPISpec-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2HttpapispecValidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: HTTPAPISpec
metadata:
  name: valid-http-api-spec
spec:
  apiKeys:
  - query: key
  attributes:
    attributes:
      api.service:
        stringValue: bookinfo.endpoints.istio-manlinl.cloud.goog
      api.version:
        stringValue: v1
  patterns:
  - attributes:
      attributes:
        api.operation:
          stringValue: getProducts
    httpMethod: GET
    uriTemplate: /productpage
`)

func testdataConfigV1alpha2HttpapispecValidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2HttpapispecValidYaml, nil
}

func testdataConfigV1alpha2HttpapispecValidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2HttpapispecValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-HTTPAPISpec-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2HttpapispecbindingInvalidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: HTTPAPISpecBinding
metadata:
  name: invalid-http-api-spec-binding
spec:
`)

func testdataConfigV1alpha2HttpapispecbindingInvalidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2HttpapispecbindingInvalidYaml, nil
}

func testdataConfigV1alpha2HttpapispecbindingInvalidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2HttpapispecbindingInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-HTTPAPISpecBinding-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2HttpapispecbindingValidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: HTTPAPISpecBinding
metadata:
  name: valid-http-api-spec-binding
spec:
  apiSpecs:
  - name: productpage
    namespace: default
  services:
  - name: productpage
    namespace: default
`)

func testdataConfigV1alpha2HttpapispecbindingValidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2HttpapispecbindingValidYaml, nil
}

func testdataConfigV1alpha2HttpapispecbindingValidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2HttpapispecbindingValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-HTTPAPISpecBinding-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2QuotaspecInvalidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: QuotaSpec
metadata:
  name: invalid-quota-spec
spec:
`)

func testdataConfigV1alpha2QuotaspecInvalidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2QuotaspecInvalidYaml, nil
}

func testdataConfigV1alpha2QuotaspecInvalidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2QuotaspecInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-QuotaSpec-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2QuotaspecValidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: QuotaSpec
metadata:
  name: valid-quota-spec
spec:
  rules:
  - match:
    - clause:
        api.operation:
          exact: getProducts
    quotas:
    - charge: "1"
      quota: read-requests
`)

func testdataConfigV1alpha2QuotaspecValidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2QuotaspecValidYaml, nil
}

func testdataConfigV1alpha2QuotaspecValidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2QuotaspecValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-QuotaSpec-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2QuotaspecbindingInvalidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: QuotaSpecBinding
metadata:
  name: valid-quota-spec-binding
spec:
`)

func testdataConfigV1alpha2QuotaspecbindingInvalidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2QuotaspecbindingInvalidYaml, nil
}

func testdataConfigV1alpha2QuotaspecbindingInvalidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2QuotaspecbindingInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-QuotaSpecBinding-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2QuotaspecbindingValidYaml = []byte(`apiVersion: config.istio.io/v1alpha2
kind: QuotaSpecBinding
metadata:
  name: valid-quota-spec-binding
spec:
  quotaSpecs:
  - name: bookinfo
    namespace: default
  services:
  - name: bookinfo
    namespace: default
`)

func testdataConfigV1alpha2QuotaspecbindingValidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2QuotaspecbindingValidYaml, nil
}

func testdataConfigV1alpha2QuotaspecbindingValidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2QuotaspecbindingValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-QuotaSpecBinding-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2RuleInvalidYaml = []byte(`apiVersion: "config.istio.io/v1alpha2"
kind: handler
metadata:
  name: handler-for-invalid-rule
spec:
  compiledAdapter: denier
  params:
    status:
      code: 7
      message: Not allowed
---
apiVersion: "config.istio.io/v1alpha2"
kind: instance
metadata:
  name: instance-for-invalid-rule
spec:
  compiledTemplate: checknothing
---
apiVersion: "config.istio.io/v1alpha2"
kind: rule
metadata:
  name: invalid-rule
spec:
  badField: foo
  match: request.headers["clnt"] == "abc"
  actions:
  - handler: handler-for-invalid-rule
    instances:
    - instance-for-invalid-rule
`)

func testdataConfigV1alpha2RuleInvalidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2RuleInvalidYaml, nil
}

func testdataConfigV1alpha2RuleInvalidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2RuleInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-rule-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataConfigV1alpha2RuleValidYaml = []byte(`apiVersion: "config.istio.io/v1alpha2"
kind: handler
metadata:
  name: handler-for-valid-rule
spec:
  compiledAdapter: denier
  params:
    status:
      code: 7
      message: Not allowed
---
apiVersion: "config.istio.io/v1alpha2"
kind: instance
metadata:
  name: instance-for-valid-rule
spec:
  compiledTemplate: checknothing
---
apiVersion: "config.istio.io/v1alpha2"
kind: rule
metadata:
  name: valid-rule
spec:
  match: request.headers["clnt"] == "abc"
  actions:
  - handler: handler-for-valid-rule
    instances:
    - instance-for-valid-rule
`)

func testdataConfigV1alpha2RuleValidYamlBytes() ([]byte, error) {
	return _testdataConfigV1alpha2RuleValidYaml, nil
}

func testdataConfigV1alpha2RuleValidYaml() (*asset, error) {
	bytes, err := testdataConfigV1alpha2RuleValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/config-v1alpha2-rule-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3DestinationruleInvalidYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: invalid-destination-rule
spec:
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
`)

func testdataNetworkingV1alpha3DestinationruleInvalidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3DestinationruleInvalidYaml, nil
}

func testdataNetworkingV1alpha3DestinationruleInvalidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3DestinationruleInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-DestinationRule-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3DestinationruleValidYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: valid-destination-rule
spec:
  host: c
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
`)

func testdataNetworkingV1alpha3DestinationruleValidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3DestinationruleValidYaml, nil
}

func testdataNetworkingV1alpha3DestinationruleValidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3DestinationruleValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-DestinationRule-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3GatewayInvalidYaml = []byte(`# Routes TCP traffic through the ingressgateway Gateway to service A.
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: invalid-gateway
spec:
  selector:
    # DO NOT CHANGE THESE LABELS
    # The ingressgateway is defined in install/kubernetes/helm/istio/values.yaml
    # with these labels
    istio: ingressgateway
`)

func testdataNetworkingV1alpha3GatewayInvalidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3GatewayInvalidYaml, nil
}

func testdataNetworkingV1alpha3GatewayInvalidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3GatewayInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-Gateway-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3GatewayValidYaml = []byte(`# Routes TCP traffic through the ingressgateway Gateway to service A.
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: valid-gateway
spec:
  selector:
    # DO NOT CHANGE THESE LABELS
    # The ingressgateway is defined in install/kubernetes/helm/istio/values.yaml
    # with these labels
    istio: ingressgateway
  servers:
  - port:
      number: 31400
      protocol: TCP
      name: tcp
    hosts:
    - a.istio-system.svc.cluster.local
`)

func testdataNetworkingV1alpha3GatewayValidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3GatewayValidYaml, nil
}

func testdataNetworkingV1alpha3GatewayValidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3GatewayValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-Gateway-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3ServiceentryInvalidSkippedYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: invalid-service-entry
spec:
  ports:
  - number: 80
    name: http
    protocol: HTTP
  discovery: DNS
  endpoints:
  # Rather than relying on an external host that might become unreachable (causing test failures)
  # we can mock the external endpoint using service t which has no sidecar.
  - address: t.istio-system.svc.cluster.local # TODO: this is brittle
    ports:
      http: 8080 # TODO test https
`)

func testdataNetworkingV1alpha3ServiceentryInvalidSkippedYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3ServiceentryInvalidSkippedYaml, nil
}

func testdataNetworkingV1alpha3ServiceentryInvalidSkippedYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3ServiceentryInvalidSkippedYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-ServiceEntry-invalid-skipped.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3ServiceentryValidSkippedYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: valid-service-entry
spec:
  hosts:
  - eu.bookinfo.com
  ports:
  - number: 80
    name: http
    protocol: HTTP
  resolution: DNS
  endpoints:
  # Rather than relying on an external host that might become unreachable (causing test failures)
  # we can mock the external endpoint using service t which has no sidecar.
  - address: t.istio-system.svc.cluster.local # TODO: this is brittle
    ports:
      http: 8080 # TODO test https
`)

func testdataNetworkingV1alpha3ServiceentryValidSkippedYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3ServiceentryValidSkippedYaml, nil
}

func testdataNetworkingV1alpha3ServiceentryValidSkippedYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3ServiceentryValidSkippedYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-ServiceEntry-valid-skipped.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3VirtualserviceInvalidYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: invalid-virtual-service
spec:
  http:
    - route:
      - destination:
          host: c
          subset: v1
        weight: 75
      - destination:
          host: c
          subset: v2
        weight: 25
`)

func testdataNetworkingV1alpha3VirtualserviceInvalidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3VirtualserviceInvalidYaml, nil
}

func testdataNetworkingV1alpha3VirtualserviceInvalidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3VirtualserviceInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-VirtualService-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataNetworkingV1alpha3VirtualserviceValidYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: valid-virtual-service
spec:
  hosts:
    - c
  http:
    - route:
      - destination:
          host: c
          subset: v1
        weight: 75
      - destination:
          host: c
          subset: v2
        weight: 25
`)

func testdataNetworkingV1alpha3VirtualserviceValidYamlBytes() ([]byte, error) {
	return _testdataNetworkingV1alpha3VirtualserviceValidYaml, nil
}

func testdataNetworkingV1alpha3VirtualserviceValidYaml() (*asset, error) {
	bytes, err := testdataNetworkingV1alpha3VirtualserviceValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/networking-v1alpha3-VirtualService-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataRbacV1alpha1ServiceroleInvalidYaml = []byte(`apiVersion: "rbac.istio.io/v1alpha1"
kind: ServiceRole
metadata:
  name: products-viewer
spec:
  rules:

`)

func testdataRbacV1alpha1ServiceroleInvalidYamlBytes() ([]byte, error) {
	return _testdataRbacV1alpha1ServiceroleInvalidYaml, nil
}

func testdataRbacV1alpha1ServiceroleInvalidYaml() (*asset, error) {
	bytes, err := testdataRbacV1alpha1ServiceroleInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/rbac-v1alpha1-ServiceRole-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataRbacV1alpha1ServiceroleValidYaml = []byte(`apiVersion: "rbac.istio.io/v1alpha1"
kind: ServiceRole
metadata:
  name: products-viewer
spec:
  rules:
  - services: ["products.svc.cluster.local"]
    methods: ["GET", "HEAD"]
    constraints:
    - key: "version"
      values: ["v1", "v2"]

`)

func testdataRbacV1alpha1ServiceroleValidYamlBytes() ([]byte, error) {
	return _testdataRbacV1alpha1ServiceroleValidYaml, nil
}

func testdataRbacV1alpha1ServiceroleValidYaml() (*asset, error) {
	bytes, err := testdataRbacV1alpha1ServiceroleValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/rbac-v1alpha1-ServiceRole-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataRbacV1alpha1ServicerolebindingInvalidYaml = []byte(`apiVersion: "rbac.istio.io/v1alpha1"
kind: ServiceRoleBinding
metadata:
  name: test-binding-products
spec:
  subjects:

`)

func testdataRbacV1alpha1ServicerolebindingInvalidYamlBytes() ([]byte, error) {
	return _testdataRbacV1alpha1ServicerolebindingInvalidYaml, nil
}

func testdataRbacV1alpha1ServicerolebindingInvalidYaml() (*asset, error) {
	bytes, err := testdataRbacV1alpha1ServicerolebindingInvalidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/rbac-v1alpha1-ServiceRoleBinding-invalid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _testdataRbacV1alpha1ServicerolebindingValidYaml = []byte(`apiVersion: "rbac.istio.io/v1alpha1"
kind: ServiceRoleBinding
metadata:
  name: test-binding-products
spec:
  subjects:
  - user: "alice@yahoo.com"
  - properties:
      service: "reviews"
      namespace: "abc"
  roleRef:
    kind: ServiceRole
    name: "products-viewer"

`)

func testdataRbacV1alpha1ServicerolebindingValidYamlBytes() ([]byte, error) {
	return _testdataRbacV1alpha1ServicerolebindingValidYaml, nil
}

func testdataRbacV1alpha1ServicerolebindingValidYaml() (*asset, error) {
	bytes, err := testdataRbacV1alpha1ServicerolebindingValidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "testdata/rbac-v1alpha1-ServiceRoleBinding-valid.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"testdata/authentication-v1alpha1-Policy-invalid.yaml":           testdataAuthenticationV1alpha1PolicyInvalidYaml,
	"testdata/authentication-v1alpha1-Policy-valid.yaml":             testdataAuthenticationV1alpha1PolicyValidYaml,
	"testdata/config-v1alpha2-HTTPAPISpec-invalid.yaml":              testdataConfigV1alpha2HttpapispecInvalidYaml,
	"testdata/config-v1alpha2-HTTPAPISpec-valid.yaml":                testdataConfigV1alpha2HttpapispecValidYaml,
	"testdata/config-v1alpha2-HTTPAPISpecBinding-invalid.yaml":       testdataConfigV1alpha2HttpapispecbindingInvalidYaml,
	"testdata/config-v1alpha2-HTTPAPISpecBinding-valid.yaml":         testdataConfigV1alpha2HttpapispecbindingValidYaml,
	"testdata/config-v1alpha2-QuotaSpec-invalid.yaml":                testdataConfigV1alpha2QuotaspecInvalidYaml,
	"testdata/config-v1alpha2-QuotaSpec-valid.yaml":                  testdataConfigV1alpha2QuotaspecValidYaml,
	"testdata/config-v1alpha2-QuotaSpecBinding-invalid.yaml":         testdataConfigV1alpha2QuotaspecbindingInvalidYaml,
	"testdata/config-v1alpha2-QuotaSpecBinding-valid.yaml":           testdataConfigV1alpha2QuotaspecbindingValidYaml,
	"testdata/config-v1alpha2-rule-invalid.yaml":                     testdataConfigV1alpha2RuleInvalidYaml,
	"testdata/config-v1alpha2-rule-valid.yaml":                       testdataConfigV1alpha2RuleValidYaml,
	"testdata/networking-v1alpha3-DestinationRule-invalid.yaml":      testdataNetworkingV1alpha3DestinationruleInvalidYaml,
	"testdata/networking-v1alpha3-DestinationRule-valid.yaml":        testdataNetworkingV1alpha3DestinationruleValidYaml,
	"testdata/networking-v1alpha3-Gateway-invalid.yaml":              testdataNetworkingV1alpha3GatewayInvalidYaml,
	"testdata/networking-v1alpha3-Gateway-valid.yaml":                testdataNetworkingV1alpha3GatewayValidYaml,
	"testdata/networking-v1alpha3-ServiceEntry-invalid-skipped.yaml": testdataNetworkingV1alpha3ServiceentryInvalidSkippedYaml,
	"testdata/networking-v1alpha3-ServiceEntry-valid-skipped.yaml":   testdataNetworkingV1alpha3ServiceentryValidSkippedYaml,
	"testdata/networking-v1alpha3-VirtualService-invalid.yaml":       testdataNetworkingV1alpha3VirtualserviceInvalidYaml,
	"testdata/networking-v1alpha3-VirtualService-valid.yaml":         testdataNetworkingV1alpha3VirtualserviceValidYaml,
	"testdata/rbac-v1alpha1-ServiceRole-invalid.yaml":                testdataRbacV1alpha1ServiceroleInvalidYaml,
	"testdata/rbac-v1alpha1-ServiceRole-valid.yaml":                  testdataRbacV1alpha1ServiceroleValidYaml,
	"testdata/rbac-v1alpha1-ServiceRoleBinding-invalid.yaml":         testdataRbacV1alpha1ServicerolebindingInvalidYaml,
	"testdata/rbac-v1alpha1-ServiceRoleBinding-valid.yaml":           testdataRbacV1alpha1ServicerolebindingValidYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"testdata": &bintree{nil, map[string]*bintree{
		"authentication-v1alpha1-Policy-invalid.yaml":           &bintree{testdataAuthenticationV1alpha1PolicyInvalidYaml, map[string]*bintree{}},
		"authentication-v1alpha1-Policy-valid.yaml":             &bintree{testdataAuthenticationV1alpha1PolicyValidYaml, map[string]*bintree{}},
		"config-v1alpha2-HTTPAPISpec-invalid.yaml":              &bintree{testdataConfigV1alpha2HttpapispecInvalidYaml, map[string]*bintree{}},
		"config-v1alpha2-HTTPAPISpec-valid.yaml":                &bintree{testdataConfigV1alpha2HttpapispecValidYaml, map[string]*bintree{}},
		"config-v1alpha2-HTTPAPISpecBinding-invalid.yaml":       &bintree{testdataConfigV1alpha2HttpapispecbindingInvalidYaml, map[string]*bintree{}},
		"config-v1alpha2-HTTPAPISpecBinding-valid.yaml":         &bintree{testdataConfigV1alpha2HttpapispecbindingValidYaml, map[string]*bintree{}},
		"config-v1alpha2-QuotaSpec-invalid.yaml":                &bintree{testdataConfigV1alpha2QuotaspecInvalidYaml, map[string]*bintree{}},
		"config-v1alpha2-QuotaSpec-valid.yaml":                  &bintree{testdataConfigV1alpha2QuotaspecValidYaml, map[string]*bintree{}},
		"config-v1alpha2-QuotaSpecBinding-invalid.yaml":         &bintree{testdataConfigV1alpha2QuotaspecbindingInvalidYaml, map[string]*bintree{}},
		"config-v1alpha2-QuotaSpecBinding-valid.yaml":           &bintree{testdataConfigV1alpha2QuotaspecbindingValidYaml, map[string]*bintree{}},
		"config-v1alpha2-rule-invalid.yaml":                     &bintree{testdataConfigV1alpha2RuleInvalidYaml, map[string]*bintree{}},
		"config-v1alpha2-rule-valid.yaml":                       &bintree{testdataConfigV1alpha2RuleValidYaml, map[string]*bintree{}},
		"networking-v1alpha3-DestinationRule-invalid.yaml":      &bintree{testdataNetworkingV1alpha3DestinationruleInvalidYaml, map[string]*bintree{}},
		"networking-v1alpha3-DestinationRule-valid.yaml":        &bintree{testdataNetworkingV1alpha3DestinationruleValidYaml, map[string]*bintree{}},
		"networking-v1alpha3-Gateway-invalid.yaml":              &bintree{testdataNetworkingV1alpha3GatewayInvalidYaml, map[string]*bintree{}},
		"networking-v1alpha3-Gateway-valid.yaml":                &bintree{testdataNetworkingV1alpha3GatewayValidYaml, map[string]*bintree{}},
		"networking-v1alpha3-ServiceEntry-invalid-skipped.yaml": &bintree{testdataNetworkingV1alpha3ServiceentryInvalidSkippedYaml, map[string]*bintree{}},
		"networking-v1alpha3-ServiceEntry-valid-skipped.yaml":   &bintree{testdataNetworkingV1alpha3ServiceentryValidSkippedYaml, map[string]*bintree{}},
		"networking-v1alpha3-VirtualService-invalid.yaml":       &bintree{testdataNetworkingV1alpha3VirtualserviceInvalidYaml, map[string]*bintree{}},
		"networking-v1alpha3-VirtualService-valid.yaml":         &bintree{testdataNetworkingV1alpha3VirtualserviceValidYaml, map[string]*bintree{}},
		"rbac-v1alpha1-ServiceRole-invalid.yaml":                &bintree{testdataRbacV1alpha1ServiceroleInvalidYaml, map[string]*bintree{}},
		"rbac-v1alpha1-ServiceRole-valid.yaml":                  &bintree{testdataRbacV1alpha1ServiceroleValidYaml, map[string]*bintree{}},
		"rbac-v1alpha1-ServiceRoleBinding-invalid.yaml":         &bintree{testdataRbacV1alpha1ServicerolebindingInvalidYaml, map[string]*bintree{}},
		"rbac-v1alpha1-ServiceRoleBinding-valid.yaml":           &bintree{testdataRbacV1alpha1ServicerolebindingValidYaml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
