// Code generated for package conversion by go-bindata DO NOT EDIT. (@generated)
// sources:
// dataset/config.istio.io/v1alpha2/rule.yaml
// dataset/config.istio.io/v1alpha2/rule_expected.json
// dataset/core/v1/namespace.yaml
// dataset/core/v1/namespace_expected.json
// dataset/core/v1/service.yaml
// dataset/core/v1/service_expected.json
// dataset/extensions/v1beta1/ingress_basic.yaml
// dataset/extensions/v1beta1/ingress_basic_expected.json
// dataset/extensions/v1beta1/ingress_basic_meshconfig.yaml
// dataset/extensions/v1beta1/ingress_merge_0.yaml
// dataset/extensions/v1beta1/ingress_merge_0_expected.json
// dataset/extensions/v1beta1/ingress_merge_0_meshconfig.yaml
// dataset/extensions/v1beta1/ingress_merge_1.yaml
// dataset/extensions/v1beta1/ingress_merge_1_expected.json
// dataset/extensions/v1beta1/ingress_multihost.yaml
// dataset/extensions/v1beta1/ingress_multihost_expected.json
// dataset/extensions/v1beta1/ingress_multihost_meshconfig.yaml
// dataset/mesh.istio.io/v1alpha1/meshconfig.yaml
// dataset/mesh.istio.io/v1alpha1/meshconfig_expected.json
// dataset/networking.istio.io/v1alpha3/destinationRule.yaml
// dataset/networking.istio.io/v1alpha3/destinationRule_expected.json
// dataset/networking.istio.io/v1alpha3/gateway.yaml
// dataset/networking.istio.io/v1alpha3/gateway_expected.json
// dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry.yaml
// dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry_expected.json
// dataset/networking.istio.io/v1alpha3/virtualService.yaml
// dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported.yaml
// dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported_expected.json
// dataset/networking.istio.io/v1alpha3/virtualService_expected.json
package conversion

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

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _datasetConfigIstioIoV1alpha2RuleYaml = []byte(`apiVersion: "config.istio.io/v1alpha2"
kind: rule
metadata:
  name: valid-rule
spec:
  actions:
  - handler: my-handler
    instances: [ my-instance ]
`)

func datasetConfigIstioIoV1alpha2RuleYamlBytes() ([]byte, error) {
	return _datasetConfigIstioIoV1alpha2RuleYaml, nil
}

func datasetConfigIstioIoV1alpha2RuleYaml() (*asset, error) {
	bytes, err := datasetConfigIstioIoV1alpha2RuleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/config.istio.io/v1alpha2/rule.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetConfigIstioIoV1alpha2Rule_expectedJson = []byte(`{
  "istio/policy/v1beta1/rules": [
    {
      "Metadata": {
        "name": "{{.Namespace}}/valid-rule"
      },
      "Body": {
        "actions": [
          {
            "handler": "my-handler",
            "instances": [
              "my-instance"
            ]
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.policy.v1beta1.Rule"
    }
  ]
}
`)

func datasetConfigIstioIoV1alpha2Rule_expectedJsonBytes() ([]byte, error) {
	return _datasetConfigIstioIoV1alpha2Rule_expectedJson, nil
}

func datasetConfigIstioIoV1alpha2Rule_expectedJson() (*asset, error) {
	bytes, err := datasetConfigIstioIoV1alpha2Rule_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/config.istio.io/v1alpha2/rule_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetCoreV1NamespaceYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: 2019-05-08T17:06:31Z
  name: default
  resourceVersion: "4"
  selfLink: /api/v1/namespaces/default
  uid: a0641b25-71b3-11e9-9fe1-42010a8a0126
spec:
  finalizers:
  - kubernetes
`)

func datasetCoreV1NamespaceYamlBytes() ([]byte, error) {
	return _datasetCoreV1NamespaceYaml, nil
}

func datasetCoreV1NamespaceYaml() (*asset, error) {
	bytes, err := datasetCoreV1NamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/core/v1/namespace.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetCoreV1Namespace_expectedJson = []byte(`{
    "k8s/core/v1/namespaces": [
        {
            "TypeURL": "type.googleapis.com/k8s.io.api.core.v1.NamespaceSpec",
            "Metadata": {
                "name": "default"
            },
            "Body": {
                "finalizers": [
                    "kubernetes"
                ]
            }
        }
    ]
}
`)

func datasetCoreV1Namespace_expectedJsonBytes() ([]byte, error) {
	return _datasetCoreV1Namespace_expectedJson, nil
}

func datasetCoreV1Namespace_expectedJson() (*asset, error) {
	bytes, err := datasetCoreV1Namespace_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/core/v1/namespace_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetCoreV1ServiceYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Service","metadata":{"annotations":{},"labels":{"addonmanager.kubernetes.io/mode":"Reconcile","k8s-app":"kube-dns","kubernetes.io/cluster-service":"true","kubernetes.io/name":"KubeDNS"},"name":"kube-dns","namespace":"kube-system"},"spec":{"clusterIP":"10.43.240.10","ports":[{"name":"dns","port":53,"protocol":"UDP"},{"name":"dns-tcp","port":53,"protocol":"TCP"}],"selector":{"k8s-app":"kube-dns"}}}
  creationTimestamp: 2018-02-12T15:48:44Z
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: KubeDNS
  name: kube-dns
  #namespace: kube-system
  resourceVersion: "274"
  selfLink: /api/v1/namespaces/kube-system/services/kube-dns
  uid: 3497d702-100c-11e8-a600-42010a8002c3
spec:
  clusterIP: 10.43.240.10
  ports:
    - name: dns
      port: 53
      protocol: UDP
      targetPort: 53
    - name: dns-tcp
      port: 53
      protocol: TCP
      targetPort: 53
  selector:
    k8s-app: kube-dns
  sessionAffinity: None
  type: ClusterIP
status:
  loadBalancer: {}`)

func datasetCoreV1ServiceYamlBytes() ([]byte, error) {
	return _datasetCoreV1ServiceYaml, nil
}

func datasetCoreV1ServiceYaml() (*asset, error) {
	bytes, err := datasetCoreV1ServiceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/core/v1/service.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetCoreV1Service_expectedJson = []byte(`{
  "k8s/core/v1/services": [
    {
      "TypeURL": "type.googleapis.com/k8s.io.api.core.v1.ServiceSpec",
      "Metadata": {
        "name": "{{.Namespace}}/kube-dns",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"labels\":{\"addonmanager.kubernetes.io/mode\":\"Reconcile\",\"k8s-app\":\"kube-dns\",\"kubernetes.io/cluster-service\":\"true\",\"kubernetes.io/name\":\"KubeDNS\"},\"name\":\"kube-dns\",\"namespace\":\"kube-system\"},\"spec\":{\"clusterIP\":\"10.43.240.10\",\"ports\":[{\"name\":\"dns\",\"port\":53,\"protocol\":\"UDP\"},{\"name\":\"dns-tcp\",\"port\":53,\"protocol\":\"TCP\"}],\"selector\":{\"k8s-app\":\"kube-dns\"}}}\n"
        },
        "labels": {
          "addonmanager.kubernetes.io/mode": "Reconcile",
          "k8s-app": "kube-dns",
          "kubernetes.io/cluster-service": "true",
          "kubernetes.io/name": "KubeDNS"
        }
      },
      "Body": {
        "clusterIP": "10.43.240.10",
        "ports": [
          {
            "name": "dns",
            "port": 53,
            "protocol": "UDP",
            "targetPort": 53
          },
          {
            "name": "dns-tcp",
            "port": 53,
            "protocol": "TCP",
            "targetPort": 53
          }
        ],
        "selector": {
          "k8s-app": "kube-dns"
        },
        "sessionAffinity": "None",
        "type": "ClusterIP"
      }
    }
  ]
}
`)

func datasetCoreV1Service_expectedJsonBytes() ([]byte, error) {
	return _datasetCoreV1Service_expectedJson, nil
}

func datasetCoreV1Service_expectedJson() (*asset, error) {
	bytes, err := datasetCoreV1Service_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/core/v1/service_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_basicYaml = []byte(`apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: foo
  annotations:
    kubernetes.io/ingress.class: "cls"

spec:
  backend:
    serviceName: "testsvc"
    servicePort: "80"
`)

func datasetExtensionsV1beta1Ingress_basicYamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_basicYaml, nil
}

func datasetExtensionsV1beta1Ingress_basicYaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_basicYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_basic.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_basic_expectedJson = []byte(`{
  "istio/networking/v1alpha3/gateways": [
    {
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway",
      "Metadata": {
        "name": "istio-system/foo-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "selector": {
          "istio": "ingress"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http-80-i-foo-{{.Namespace}}",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      }
    }
  ],

  "istio/networking/v1alpha3/virtualservices": [
  ]
}
`)

func datasetExtensionsV1beta1Ingress_basic_expectedJsonBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_basic_expectedJson, nil
}

func datasetExtensionsV1beta1Ingress_basic_expectedJson() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_basic_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_basic_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_basic_meshconfigYaml = []byte(`ingressClass: cls
ingressControllerMode: STRICT
`)

func datasetExtensionsV1beta1Ingress_basic_meshconfigYamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_basic_meshconfigYaml, nil
}

func datasetExtensionsV1beta1Ingress_basic_meshconfigYaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_basic_meshconfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_basic_meshconfig.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_merge_0Yaml = []byte(`apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: foo
  namespace: ns
  annotations:
    kubernetes.io/ingress.class: "cls"
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /foo
        backend:
          serviceName: service1
          servicePort: 4200
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: bar
  namespace: ns
  annotations:
    kubernetes.io/ingress.class: "cls"
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /bar
        backend:
          serviceName: service2
          servicePort: 2400
---
`)

func datasetExtensionsV1beta1Ingress_merge_0YamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_merge_0Yaml, nil
}

func datasetExtensionsV1beta1Ingress_merge_0Yaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_merge_0YamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_merge_0.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_merge_0_expectedJson = []byte(`{
  "istio/networking/v1alpha3/gateways": [
    {
      "Metadata": {
        "name": "istio-system/bar-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "selector": {
          "istio": "ingress"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http-80-i-bar-{{.Namespace}}",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway"
    },
    {
      "Metadata": {
        "name": "istio-system/foo-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "selector": {
          "istio": "ingress"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http-80-i-foo-{{.Namespace}}",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway"
    }
  ],

  "istio/networking/v1alpha3/virtualservices": [
    {
      "Metadata": {
        "name": "istio-system/foo-bar-com-bar-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "gateways": [
          "istio-autogenerated-k8s-ingress"
        ],
        "hosts": [
          "foo.bar.com"
        ],
        "http": [
          {
            "match": [
              {
                "uri": {
                  "exact": "/bar"
                }
              }
            ],
            "route": [
              {
                "destination": {
                  "host": "service2.{{.Namespace}}.svc.cluster.local",
                  "port": {
                    "number": 2400
                  }
                },
                "weight": 100
              }
            ]
          },
          {
            "match": [
              {
                "uri": {
                  "exact": "/foo"
                }
              }
            ],
            "route": [
              {
                "destination": {
                  "host": "service1.{{.Namespace}}.svc.cluster.local",
                  "port": {
                    "number": 4200
                  }
                },
                "weight": 100
              }
            ]
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
    }
  ]
}
`)

func datasetExtensionsV1beta1Ingress_merge_0_expectedJsonBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_merge_0_expectedJson, nil
}

func datasetExtensionsV1beta1Ingress_merge_0_expectedJson() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_merge_0_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_merge_0_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_merge_0_meshconfigYaml = []byte(`ingressClass: cls
ingressControllerMode: STRICT
`)

func datasetExtensionsV1beta1Ingress_merge_0_meshconfigYamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_merge_0_meshconfigYaml, nil
}

func datasetExtensionsV1beta1Ingress_merge_0_meshconfigYaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_merge_0_meshconfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_merge_0_meshconfig.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_merge_1Yaml = []byte(`apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: foo
  namespace: ns
  annotations:
    kubernetes.io/ingress.class: "cls"
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /foo
        backend:
          serviceName: service1
          servicePort: 4200
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: bar
  namespace: ns
  annotations:
    kubernetes.io/ingress.class: "cls"
spec:
  rules:
  - host: foo.bar.com
    http:
      paths:
      - path: /bar
        backend:
          # The service has changed since the initial config.
          serviceName: service5
          servicePort: 5000
---
`)

func datasetExtensionsV1beta1Ingress_merge_1YamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_merge_1Yaml, nil
}

func datasetExtensionsV1beta1Ingress_merge_1Yaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_merge_1YamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_merge_1.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_merge_1_expectedJson = []byte(`{
  "istio/networking/v1alpha3/gateways": [
    {
      "Metadata": {
        "name": "istio-system/bar-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "selector": {
          "istio": "ingress"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http-80-i-bar-{{.Namespace}}",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway"
    },
    {
      "Metadata": {
        "name": "istio-system/foo-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "selector": {
          "istio": "ingress"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http-80-i-foo-{{.Namespace}}",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway"
    }
  ],

  "istio/networking/v1alpha3/virtualservices": [
    {
      "Metadata": {
        "name": "istio-system/foo-bar-com-bar-istio-autogenerated-k8s-ingress"
      },
      "Body": {
        "gateways": [
          "istio-autogenerated-k8s-ingress"
        ],
        "hosts": [
          "foo.bar.com"
        ],
        "http": [
          {
            "match": [
              {
                "uri": {
                  "exact": "/bar"
                }
              }
            ],
            "route": [
              {
                "destination": {
                  "host": "service5.{{.Namespace}}.svc.cluster.local",
                  "port": {
                    "number": 5000
                  }
                },
                "weight": 100
              }
            ]
          },
          {
            "match": [
              {
                "uri": {
                  "exact": "/foo"
                }
              }
            ],
            "route": [
              {
                "destination": {
                  "host": "service1.{{.Namespace}}.svc.cluster.local",
                  "port": {
                    "number": 4200
                  }
                },
                "weight": 100
              }
            ]
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
    }
  ]
}
`)

func datasetExtensionsV1beta1Ingress_merge_1_expectedJsonBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_merge_1_expectedJson, nil
}

func datasetExtensionsV1beta1Ingress_merge_1_expectedJson() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_merge_1_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_merge_1_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_multihostYaml = []byte(`apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: echo
  annotations:
    kubernetes.io/ingress.class: cls
spec:
  rules:
  - host: echo1.example.com
    http:
      paths:
      - backend:
          serviceName: echo1
          servicePort: 80
  - host: echo2.example.com
    http:
      paths:
      - backend:
          serviceName: echo2
          servicePort: 80`)

func datasetExtensionsV1beta1Ingress_multihostYamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_multihostYaml, nil
}

func datasetExtensionsV1beta1Ingress_multihostYaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_multihostYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_multihost.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_multihost_expectedJson = []byte(`{
    "istio/networking/v1alpha3/gateways": [
        {
            "Metadata": {
                "name": "istio-system/echo-istio-autogenerated-k8s-ingress"
            },
            "Body": {
                "selector": {
                    "istio": "ingress"
                },
                "servers": [
                    {
                        "hosts": [
                            "*"
                        ],
                        "port": {
                            "name": "http-80-i-echo-{{.Namespace}}",
                            "number": 80,
                            "protocol": "HTTP"
                        }
                    }
                ]
            },
            "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway"
        }
    ],
    "istio/networking/v1alpha3/virtualservices": [
        {
            "Metadata": {
                "name": "istio-system/echo1-example-com-echo-istio-autogenerated-k8s-ingress"
            },
            "Body": {
                "gateways": [
                    "istio-autogenerated-k8s-ingress"
                ],
                "hosts": [
                    "echo1.example.com"
                ],
                "http": [
                    {
                        "match": [
                            {}
                        ],
                        "route": [
                            {
                                "destination": {
                                    "host": "echo1.{{.Namespace}}.svc.cluster.local",
                                    "port": {
                                        "number": 80
                                    }
                                },
                                "weight": 100
                            }
                        ]
                    }
                ]
            },
            "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
        },
        {
            "Metadata": {
                "name": "istio-system/echo2-example-com-echo-istio-autogenerated-k8s-ingress"
            },
            "Body": {
                "gateways": [
                    "istio-autogenerated-k8s-ingress"
                ],
                "hosts": [
                    "echo2.example.com"
                ],
                "http": [
                    {
                        "match": [
                            {}
                        ],
                        "route": [
                            {
                                "destination": {
                                    "host": "echo2.{{.Namespace}}.svc.cluster.local",
                                    "port": {
                                        "number": 80
                                    }
                                },
                                "weight": 100
                            }
                        ]
                    }
                ]
            },
            "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
        }
    ]
}`)

func datasetExtensionsV1beta1Ingress_multihost_expectedJsonBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_multihost_expectedJson, nil
}

func datasetExtensionsV1beta1Ingress_multihost_expectedJson() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_multihost_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_multihost_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetExtensionsV1beta1Ingress_multihost_meshconfigYaml = []byte(`ingressClass: cls
ingressControllerMode: STRICT
`)

func datasetExtensionsV1beta1Ingress_multihost_meshconfigYamlBytes() ([]byte, error) {
	return _datasetExtensionsV1beta1Ingress_multihost_meshconfigYaml, nil
}

func datasetExtensionsV1beta1Ingress_multihost_meshconfigYaml() (*asset, error) {
	bytes, err := datasetExtensionsV1beta1Ingress_multihost_meshconfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/extensions/v1beta1/ingress_multihost_meshconfig.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetMeshIstioIoV1alpha1MeshconfigYaml = []byte(``)

func datasetMeshIstioIoV1alpha1MeshconfigYamlBytes() ([]byte, error) {
	return _datasetMeshIstioIoV1alpha1MeshconfigYaml, nil
}

func datasetMeshIstioIoV1alpha1MeshconfigYaml() (*asset, error) {
	bytes, err := datasetMeshIstioIoV1alpha1MeshconfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/mesh.istio.io/v1alpha1/meshconfig.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetMeshIstioIoV1alpha1Meshconfig_expectedJson = []byte(`{
    "istio/mesh/v1alpha1/MeshConfig": [
        {
            "TypeURL": "type.googleapis.com/istio.mesh.v1alpha1.MeshConfig",
            "Metadata": {
                "name": "istio-system/meshconfig"
            },
            "Body": {
                "access_log_file": "/dev/stdout",
                "connect_timeout": {
                    "seconds": 1
                },
                "default_config": {
                  "binary_path": "/usr/local/bin/envoy",
                  "config_path": "/etc/istio/proxy",
                  "connect_timeout": {
                    "seconds": 1
                  },
                  "discovery_address": "istio-pilot:15010",
                  "drain_duration": {
                    "seconds": 45
                  },
                  "envoy_access_log_service": {},
                  "envoy_metrics_service": {},
                  "parent_shutdown_duration": {
                    "seconds": 60
                  },
                  "proxy_admin_port": 15000,
                  "service_cluster": "istio-proxy",
                  "stat_name_length": 189
                },
                "default_destination_rule_export_to": [
                  "*"
                ],
                "default_service_export_to": [
                  "*"
                ],
                "default_virtual_service_export_to": [
                  "*"
                ],
                "disable_policy_checks": true,
                "dns_refresh_rate": {
                  "seconds": 5
                },
                "enable_auto_mtls": {},
                "enable_tracing": true,
                "ingress_class": "istio",
                "ingress_controller_mode": 2,
                "ingress_service": "istio-ingressgateway",
                "outbound_traffic_policy": {
                    "mode": 1
                },
                "protocol_detection_timeout": {
                  "nanos": 100000000
                },
                "proxy_listen_port": 15001,
                "root_namespace": "istio-system"
            }
        }
    ]
}
`)

func datasetMeshIstioIoV1alpha1Meshconfig_expectedJsonBytes() ([]byte, error) {
	return _datasetMeshIstioIoV1alpha1Meshconfig_expectedJson, nil
}

func datasetMeshIstioIoV1alpha1Meshconfig_expectedJson() (*asset, error) {
	bytes, err := datasetMeshIstioIoV1alpha1Meshconfig_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/mesh.istio.io/v1alpha1/meshconfig_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3DestinationruleYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: tcp-echo-destination
spec:
  host: tcp-echo
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
`)

func datasetNetworkingIstioIoV1alpha3DestinationruleYamlBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3DestinationruleYaml, nil
}

func datasetNetworkingIstioIoV1alpha3DestinationruleYaml() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3DestinationruleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/destinationRule.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJson = []byte(`{
  "istio/networking/v1alpha3/destinationrules": [
    {
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.DestinationRule",
      "Metadata": {
        "name": "{{.Namespace}}/tcp-echo-destination"
      },
      "Body": {
        "host": "tcp-echo",
        "subsets": [
          {
            "labels": {
              "version": "v1"
            },
            "name": "v1"
          },
          {
            "labels": {
              "version": "v2"
            },
            "name": "v2"
          }
        ]
      }
    }
  ]
}
`)

func datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJsonBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJson, nil
}

func datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJson() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/destinationRule_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3GatewayYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: helloworld-gateway
spec:
  selector:
    istio: ingressgateway # use istio default controller
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
`)

func datasetNetworkingIstioIoV1alpha3GatewayYamlBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3GatewayYaml, nil
}

func datasetNetworkingIstioIoV1alpha3GatewayYaml() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3GatewayYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/gateway.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3Gateway_expectedJson = []byte(`{
  "istio/networking/v1alpha3/gateways": [
    {
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.Gateway",
      "Metadata": {
        "name": "{{.Namespace}}/helloworld-gateway"
      },
      "Body": {
        "selector": {
          "istio": "ingressgateway"
        },
        "servers": [
          {
            "hosts": [
              "*"
            ],
            "port": {
              "name": "http",
              "number": 80,
              "protocol": "HTTP"
            }
          }
        ]
      }
    }
  ]
}
`)

func datasetNetworkingIstioIoV1alpha3Gateway_expectedJsonBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3Gateway_expectedJson, nil
}

func datasetNetworkingIstioIoV1alpha3Gateway_expectedJson() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3Gateway_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/gateway_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYaml = []byte(`apiVersion: v1
kind: Node
metadata:
  annotations:
    container.googleapis.com/instance_id: "2787417306096525587"
    node.alpha.kubernetes.io/ttl: "0"
    volumes.kubernetes.io/controller-managed-attach-detach: "true"
  creationTimestamp: 2018-10-05T19:40:48Z
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/fluentd-ds-ready: "true"
    beta.kubernetes.io/instance-type: n1-standard-4
    beta.kubernetes.io/os: linux
    cloud.google.com/gke-nodepool: default-pool
    cloud.google.com/gke-os-distribution: cos
    failure-domain.beta.kubernetes.io/region: us-central1
    failure-domain.beta.kubernetes.io/zone: us-central1-a
    kubernetes.io/hostname: gke-istio-test-default-pool-866a0405-420r
  name: gke-istio-test-default-pool-866a0405-420r
  resourceVersion: "64030398"
  selfLink: /api/v1/nodes/gke-istio-test-default-pool-866a0405-420r
  uid: 8f63dfef-c8d6-11e8-8901-42010a800278
spec:
  externalID: "1929748586650271976"
  podCIDR: 10.40.0.0/24
  providerID: gce://nathanmittler-istio-test/us-central1-a/gke-istio-test-default-pool-866a0405-420r
status:
  addresses:
    - address: 10.128.0.4
      type: InternalIP
    - address: 35.238.214.129
      type: ExternalIP
    - address: gke-istio-test-default-pool-866a0405-420r
      type: Hostname
  allocatable:
    cpu: 3920m
    ephemeral-storage: "47093746742"
    hugepages-2Mi: "0"
    memory: 12699980Ki
    pods: "110"
  capacity:
    cpu: "4"
    ephemeral-storage: 98868448Ki
    hugepages-2Mi: "0"
    memory: 15399244Ki
    pods: "110"
  conditions:
    - lastHeartbeatTime: 2019-01-30T17:33:09Z
      lastTransitionTime: 2018-12-03T17:00:58Z
      message: node is functioning properly
      reason: UnregisterNetDevice
      status: "False"
      type: FrequentUnregisterNetDevice
    - lastHeartbeatTime: 2019-01-30T17:33:09Z
      lastTransitionTime: 2018-12-03T16:55:56Z
      message: kernel has no deadlock
      reason: KernelHasNoDeadlock
      status: "False"
      type: KernelDeadlock
    - lastHeartbeatTime: 2018-10-05T19:40:58Z
      lastTransitionTime: 2018-10-05T19:40:58Z
      message: RouteController created a route
      reason: RouteCreated
      status: "False"
      type: NetworkUnavailable
    - lastHeartbeatTime: 2019-01-30T17:33:52Z
      lastTransitionTime: 2018-12-03T16:55:57Z
      message: kubelet has sufficient disk space available
      reason: KubeletHasSufficientDisk
      status: "False"
      type: OutOfDisk
    - lastHeartbeatTime: 2019-01-30T17:33:52Z
      lastTransitionTime: 2018-12-03T16:55:57Z
      message: kubelet has sufficient memory available
      reason: KubeletHasSufficientMemory
      status: "False"
      type: MemoryPressure
    - lastHeartbeatTime: 2019-01-30T17:33:52Z
      lastTransitionTime: 2018-12-03T16:55:57Z
      message: kubelet has no disk pressure
      reason: KubeletHasNoDiskPressure
      status: "False"
      type: DiskPressure
    - lastHeartbeatTime: 2019-01-30T17:33:52Z
      lastTransitionTime: 2018-10-05T19:40:48Z
      message: kubelet has sufficient PID available
      reason: KubeletHasSufficientPID
      status: "False"
      type: PIDPressure
    - lastHeartbeatTime: 2019-01-30T17:33:52Z
      lastTransitionTime: 2018-12-03T16:56:07Z
      message: kubelet is posting ready status. AppArmor enabled
      reason: KubeletReady
      status: "True"
      type: Ready
  daemonEndpoints:
    kubeletEndpoint:
      Port: 10250
  images:
    - names:
        - gcr.io/stackdriver-agents/stackdriver-logging-agent@sha256:a33f69d0034fdce835a1eb7df8a051ea74323f3fc30d911bbd2e3f2aef09fc93
        - gcr.io/stackdriver-agents/stackdriver-logging-agent:0.3-1.5.34-1-k8s-1
      sizeBytes: 554981103
    - names:
        - istio/examples-bookinfo-reviews-v2@sha256:d2483dcb235b27309680177726e4e86905d66e47facaf1d57ed590b2bf95c8ad
        - istio/examples-bookinfo-reviews-v2:1.9.0
      sizeBytes: 525074812
    - names:
        - istio/examples-bookinfo-reviews-v1@sha256:920d46b3c526376b28b90d0e895ca7682d36132e6338301fcbcd567ef81bde05
        - istio/examples-bookinfo-reviews-v1:1.9.0
      sizeBytes: 525074812
    - names:
        - istio/examples-bookinfo-reviews-v3@sha256:8c0385f0ca799e655d8770b52cb4618ba54e8966a0734ab1aeb6e8b14e171a3b
        - istio/examples-bookinfo-reviews-v3:1.9.0
      sizeBytes: 525074812
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:8cea2c055dd3d3ab78f99584256efcc1cff7d8ddbed11cded404e9d164235502
      sizeBytes: 448337138
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:23a52850819d5196d66e8e20f4f63f314f779716f830e1d109ad0e24b1f0df43
      sizeBytes: 446407220
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:fc1f957cfa26673768be8fa865066f730f22fde98a6e80654d00f755a643b507
      sizeBytes: 446407220
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:9949bc22667ef88e54ae91700a64bf1459e8c14ed92b870b7ec2f630e14cf3c1
      sizeBytes: 446407220
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:e338c2c5cbc379db24c5b2d67a4acc9cca9a069c2927217fca0ce7cbc582d312
      sizeBytes: 446398900
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:039dbddf8498eff82b25b04cd35c81c4f3e350a1c34e1b128bb0199d6e7d4f98
        - gcr.io/nathanmittler-istio-test/proxyv2:latest
      sizeBytes: 368758526
    - names:
        - gcr.io/istio-release/proxyv2@sha256:dec972eab4f46c974feec1563ea484ad4995edf55ea91d42e148c5db04b3d4d2
        - gcr.io/istio-release/proxyv2:master-latest-daily
      sizeBytes: 353271308
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:cb4a29362ff9014bf1d96e0ce2bb6337bf034908bb4a8d48af0628a4d8d64413
      sizeBytes: 344543156
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:9d502fd29961bc3464f7906ac0e86b07edf01cf4892352ef780e55b3525fb0b8
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:3f4115cd8c26a17f6bf8ea49f1ff5b875382bda5a6d46281c70c886e802666b0
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:cdd2f527b4bd392b533d2d0e62c257c19d5a35a6b5fc3512aa327c560866aec1
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:6ec1dced4cee8569c77817927938fa4341f939e0dddab511bc3ee8724d652ae2
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:58a7511f549448f6f86280559069bc57f5c754877ebec69da5bbc7ad55e42162
      sizeBytes: 344201616
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:4e75c42518bb46376cfe0b4fbaa3da1d8f1cea99f706736f1b0b04a3ac554db2
      sizeBytes: 344201616
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:7f60a750d15cda9918e9172e529270ce78c670751d4027f6adc6bdc84ec2d884
      sizeBytes: 344201436
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:6fc25c08212652c7539caaf0f6d913d929f84c54767f20066657ce0f4e6a51e0
      sizeBytes: 344193424
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:4e93825950c831ce6d2b65c9a80921c8860035e39a4b384d38d40f7d2cb2a4ee
      sizeBytes: 344185232
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:842216399613774640a4605202d446cf61bd48ff20e12391a0239cbc6a8f2c77
      sizeBytes: 344185052
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:8ee2bb6fc5484373227b17e377fc226d8d19be11d38d6dbc304970bd46bc929b
      sizeBytes: 344159662
    - names:
        - gcr.io/nathanmittler-istio-test/app@sha256:e141f14e7d872dcf855e09eceb411dc427188d0617fd18d14139db4ca99d2d0b
        - gcr.io/nathanmittler-istio-test/app:latest
      sizeBytes: 315430434
    - names:
        - gcr.io/nathanmittler-istio-test/pilot@sha256:01ccc7cbb36d41a58aa7d8a44ff5d3a996541bb8b7af7c215d79d13528b313ab
        - gcr.io/nathanmittler-istio-test/pilot:latest
      sizeBytes: 308784363
  nodeInfo:
    architecture: amd64
    bootID: 8f772c7c-09eb-41eb-8bb5-76ef214eaaa1
    containerRuntimeVersion: docker://17.3.2
    kernelVersion: 4.14.65+
    kubeProxyVersion: v1.11.3-gke.18
    kubeletVersion: v1.11.3-gke.18
    machineID: f325f89cd295bdcda652fd40f0049e32
    operatingSystem: linux
    osImage: Container-Optimized OS from Google
    systemUUID: F325F89C-D295-BDCD-A652-FD40F0049E32
---
apiVersion: v1
kind: Node
metadata:
  annotations:
    container.googleapis.com/instance_id: "1656674321116487208"
    node.alpha.kubernetes.io/ttl: "0"
    volumes.kubernetes.io/controller-managed-attach-detach: "true"
  creationTimestamp: 2018-12-03T16:59:36Z
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/fluentd-ds-ready: "true"
    beta.kubernetes.io/instance-type: n1-standard-4
    beta.kubernetes.io/os: linux
    cloud.google.com/gke-nodepool: default-pool
    cloud.google.com/gke-os-distribution: cos
    failure-domain.beta.kubernetes.io/region: us-central1
    failure-domain.beta.kubernetes.io/zone: us-central1-a
    kubernetes.io/hostname: gke-istio-test-default-pool-866a0405-ftch
  name: gke-istio-test-default-pool-866a0405-ftch
  resourceVersion: "64030615"
  selfLink: /api/v1/nodes/gke-istio-test-default-pool-866a0405-ftch
  uid: d0cad69e-f71c-11e8-af4f-42010a800072
spec:
  podCIDR: 10.40.1.0/24
  providerID: gce://nathanmittler-istio-test/us-central1-a/gke-istio-test-default-pool-866a0405-ftch
status:
  addresses:
    - address: 10.128.0.5
      type: InternalIP
    - address: 35.192.33.12
      type: ExternalIP
    - address: gke-istio-test-default-pool-866a0405-ftch
      type: Hostname
  allocatable:
    cpu: 3920m
    ephemeral-storage: "47093746742"
    hugepages-2Mi: "0"
    memory: 12699980Ki
    pods: "110"
  capacity:
    cpu: "4"
    ephemeral-storage: 98868448Ki
    hugepages-2Mi: "0"
    memory: 15399244Ki
    pods: "110"
  conditions:
    - lastHeartbeatTime: 2019-01-30T17:34:22Z
      lastTransitionTime: 2018-12-03T17:04:22Z
      message: node is functioning properly
      reason: UnregisterNetDevice
      status: "False"
      type: FrequentUnregisterNetDevice
    - lastHeartbeatTime: 2019-01-30T17:34:22Z
      lastTransitionTime: 2018-12-03T16:59:20Z
      message: kernel has no deadlock
      reason: KernelHasNoDeadlock
      status: "False"
      type: KernelDeadlock
    - lastHeartbeatTime: 2018-12-03T16:59:46Z
      lastTransitionTime: 2018-12-03T16:59:46Z
      message: RouteController created a route
      reason: RouteCreated
      status: "False"
      type: NetworkUnavailable
    - lastHeartbeatTime: 2019-01-30T17:35:16Z
      lastTransitionTime: 2018-12-03T16:59:36Z
      message: kubelet has sufficient disk space available
      reason: KubeletHasSufficientDisk
      status: "False"
      type: OutOfDisk
    - lastHeartbeatTime: 2019-01-30T17:35:16Z
      lastTransitionTime: 2018-12-03T16:59:36Z
      message: kubelet has sufficient memory available
      reason: KubeletHasSufficientMemory
      status: "False"
      type: MemoryPressure
    - lastHeartbeatTime: 2019-01-30T17:35:16Z
      lastTransitionTime: 2018-12-03T16:59:36Z
      message: kubelet has no disk pressure
      reason: KubeletHasNoDiskPressure
      status: "False"
      type: DiskPressure
    - lastHeartbeatTime: 2019-01-30T17:35:16Z
      lastTransitionTime: 2018-12-03T16:59:36Z
      message: kubelet has sufficient PID available
      reason: KubeletHasSufficientPID
      status: "False"
      type: PIDPressure
    - lastHeartbeatTime: 2019-01-30T17:35:16Z
      lastTransitionTime: 2018-12-03T16:59:57Z
      message: kubelet is posting ready status. AppArmor enabled
      reason: KubeletReady
      status: "True"
      type: Ready
  daemonEndpoints:
    kubeletEndpoint:
      Port: 10250
  images:
    - names:
        - gcr.io/stackdriver-agents/stackdriver-logging-agent@sha256:a33f69d0034fdce835a1eb7df8a051ea74323f3fc30d911bbd2e3f2aef09fc93
        - gcr.io/stackdriver-agents/stackdriver-logging-agent:0.3-1.5.34-1-k8s-1
      sizeBytes: 554981103
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:23a52850819d5196d66e8e20f4f63f314f779716f830e1d109ad0e24b1f0df43
      sizeBytes: 446407220
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:9949bc22667ef88e54ae91700a64bf1459e8c14ed92b870b7ec2f630e14cf3c1
      sizeBytes: 446407220
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:e338c2c5cbc379db24c5b2d67a4acc9cca9a069c2927217fca0ce7cbc582d312
      sizeBytes: 446398900
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:039dbddf8498eff82b25b04cd35c81c4f3e350a1c34e1b128bb0199d6e7d4f98
        - gcr.io/nathanmittler-istio-test/proxyv2:latest
      sizeBytes: 368758526
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:cdd2f527b4bd392b533d2d0e62c257c19d5a35a6b5fc3512aa327c560866aec1
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:6ec1dced4cee8569c77817927938fa4341f939e0dddab511bc3ee8724d652ae2
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:9d502fd29961bc3464f7906ac0e86b07edf01cf4892352ef780e55b3525fb0b8
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/proxyv2@sha256:3f4115cd8c26a17f6bf8ea49f1ff5b875382bda5a6d46281c70c886e802666b0
      sizeBytes: 344257154
    - names:
        - gcr.io/nathanmittler-istio-test/app@sha256:e141f14e7d872dcf855e09eceb411dc427188d0617fd18d14139db4ca99d2d0b
        - gcr.io/nathanmittler-istio-test/app:latest
      sizeBytes: 315430434
    - names:
        - gcr.io/nathanmittler-istio-test/app@sha256:430bdea6c4c1447dff4e8d2e9632da5211529375c45a22722dcc1500da9b95dd
      sizeBytes: 291266578
    - names:
        - gcr.io/nathanmittler-istio-test/app@sha256:ffaa484f413d324047fe000fbcc90d9195da99b681feb7c2ce8ce38f71724aec
      sizeBytes: 291230128
    - names:
        - k8s.gcr.io/node-problem-detector@sha256:f95cab985c26b2f46e9bd43283e0bfa88860c14e0fb0649266babe8b65e9eb2b
        - k8s.gcr.io/node-problem-detector:v0.4.1
      sizeBytes: 286572743
    - names:
        - gcr.io/stackdriver-agents/stackdriver-logging-agent@sha256:441f6b6a118173ec3d17d5b0c1e74824fadad6d9f1aaa5cb08ae4338f314a06c
        - gcr.io/stackdriver-agents/stackdriver-logging-agent:0.5-1.5.36-1-k8s
      sizeBytes: 218848834
    - names:
        - k8s.gcr.io/fluentd-elasticsearch@sha256:b8c94527b489fb61d3d81ce5ad7f3ddbb7be71e9620a3a36e2bede2f2e487d73
        - k8s.gcr.io/fluentd-elasticsearch:v2.0.4
      sizeBytes: 135716379
    - names:
        - gcr.io/nathanmittler-istio-test/proxy_init@sha256:636193003388dbb67215ad58a8bae7f47a7ee7b378a0e80feb3301c82075f93e
        - gcr.io/nathanmittler-istio-test/proxy_init:latest
      sizeBytes: 118960405
    - names:
        - k8s.gcr.io/fluentd-gcp-scaler@sha256:bfd8ffbadf5cbfc7cd0944f5c13aaa8da421e3ab2322d610e64c4d7de9424c29
        - k8s.gcr.io/fluentd-gcp-scaler:0.3
      sizeBytes: 115128950
    - names:
        - gcr.io/google_containers/kube-proxy:v1.11.3-gke.18
        - k8s.gcr.io/kube-proxy:v1.11.3-gke.18
      sizeBytes: 102652198
    - names:
        - k8s.gcr.io/kubernetes-dashboard-amd64@sha256:dc4026c1b595435ef5527ca598e1e9c4343076926d7d62b365c44831395adbd0
        - k8s.gcr.io/kubernetes-dashboard-amd64:v1.8.3
      sizeBytes: 102319441
    - names:
        - k8s.gcr.io/prometheus-to-sd@sha256:6c0c742475363d537ff059136e5d5e4ab1f512ee0fd9b7ca42ea48bc309d1662
        - k8s.gcr.io/prometheus-to-sd:v0.3.1
      sizeBytes: 88077694
    - names:
        - k8s.gcr.io/kube-addon-manager@sha256:3519273916ba45cfc9b318448d4629819cb5fbccbb0822cce054dd8c1f68cb60
        - k8s.gcr.io/kube-addon-manager:v8.6
      sizeBytes: 78384272
    - names:
        - k8s.gcr.io/heapster-amd64@sha256:9fae0af136ce0cf4f88393b3670f7139ffc464692060c374d2ae748e13144521
        - k8s.gcr.io/heapster-amd64:v1.6.0-beta.1
      sizeBytes: 76016169
    - names:
        - gcr.io/nathanmittler-istio-test/mixer@sha256:f7f39c2aa2445f0eeb974e052495bea0b182054b87fb130929e3e3a11b89178c
        - gcr.io/nathanmittler-istio-test/mixer:latest
      sizeBytes: 67962964
    - names:
        - k8s.gcr.io/ingress-gce-glbc-amd64@sha256:31d36bbd9c44caffa135fc78cf0737266fcf25e3cf0cd1c2fcbfbc4f7309cc52
        - k8s.gcr.io/ingress-gce-glbc-amd64:v1.1.1
      sizeBytes: 67801919
    - names:
        - gcr.io/nathanmittler-istio-test/mixer@sha256:8b95223097646bca9ea8de2d410a55aba287868e458a34cd6b414b1cd53a994d
      sizeBytes: 67690667
  nodeInfo:
    architecture: amd64
    bootID: a4687372-7eb1-4a05-913d-2f5cb2d97194
    containerRuntimeVersion: docker://17.3.2
    kernelVersion: 4.14.65+
    kubeProxyVersion: v1.11.3-gke.18
    kubeletVersion: v1.11.3-gke.18
    machineID: e11072430320008f166ee8b71cc69999
    operatingSystem: linux
    osImage: Container-Optimized OS from Google
    systemUUID: E1107243-0320-008F-166E-E8B71CC69999
---
apiVersion: v1
kind: Pod
metadata:
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ""
    seccomp.security.alpha.kubernetes.io/pod: docker/default
  creationTimestamp: 2018-12-03T17:03:48Z
  generateName: kube-dns-548976df6c-
  labels:
    k8s-app: kube-dns
    pod-template-hash: "123"
  name: kube-dns-548976df6c-kxnhb
  #namespace: kube-system
  ownerReferences:
    - apiVersion: apps/v1
      blockOwnerDeletion: true
      controller: true
      kind: ReplicaSet
      name: kube-dns-548976df6c
      uid: b589a851-f71b-11e8-af4f-42010a800072
  resourceVersion: "50573379"
  selfLink: /api/v1/namespaces/kube-system/pods/kube-dns-548976df6c-kxnhb
  uid: 66b0ca7d-f71d-11e8-af4f-42010a800072
spec:
  containers:
    - args:
        - --domain=cluster.local.
        - --dns-port=10053
        - --config-dir=/kube-dns-config
        - --v=2
      env:
        - name: PROMETHEUS_PORT
          value: "10055"
      image: k8s.gcr.io/k8s-dns-kube-dns-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /healthcheck/kubedns
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: kubedns
      ports:
        - containerPort: 10053
          name: dns-local
          protocol: UDP
        - containerPort: 10053
          name: dns-tcp-local
          protocol: TCP
        - containerPort: 10055
          name: metrics
          protocol: TCP
      readinessProbe:
        failureThreshold: 3
        httpGet:
          path: /readiness
          port: 8081
          scheme: HTTP
        initialDelaySeconds: 3
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      resources:
        limits:
          memory: 170Mi
        requests:
          cpu: 100m
          memory: 70Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /kube-dns-config
          name: kube-dns-config
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - args:
        - -v=2
        - -logtostderr
        - -configDir=/etc/k8s/dns/dnsmasq-nanny
        - -restartDnsmasq=true
        - --
        - -k
        - --cache-size=1000
        - --no-negcache
        - --log-facility=-
        - --server=/cluster.local/127.0.0.1#10053
        - --server=/in-addr.arpa/127.0.0.1#10053
        - --server=/ip6.arpa/127.0.0.1#10053
      image: k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /healthcheck/dnsmasq
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: dnsmasq
      ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
      resources:
        requests:
          cpu: 150m
          memory: 20Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /etc/k8s/dns/dnsmasq-nanny
          name: kube-dns-config
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - args:
        - --v=2
        - --logtostderr
        - --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
        - --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
      image: k8s.gcr.io/k8s-dns-sidecar-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /metrics
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: sidecar
      ports:
        - containerPort: 10054
          name: metrics
          protocol: TCP
      resources:
        requests:
          cpu: 10m
          memory: 20Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - command:
        - /monitor
        - --component=kubedns
        - --target-port=10054
        - --stackdriver-prefix=container.googleapis.com/internal/addons
        - --api-override=https://monitoring.googleapis.com/
        - --whitelisted-metrics=probe_kubedns_latency_ms,probe_kubedns_errors,dnsmasq_misses,dnsmasq_hits
        - --pod-id=$(POD_NAME)
        - --namespace-id=$(POD_NAMESPACE)
        - --v=2
      env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
      image: gcr.io/google-containers/prometheus-to-sd:v0.2.3
      imagePullPolicy: IfNotPresent
      name: prometheus-to-sd
      resources: {}
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
  dnsPolicy: Default
  nodeName: gke-istio-test-default-pool-866a0405-420r
  priority: 2000000000
  priorityClassName: system-cluster-critical
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: kube-dns
  serviceAccountName: kube-dns
  terminationGracePeriodSeconds: 30
  tolerations:
    - key: CriticalAddonsOnly
      operator: Exists
    - effect: NoExecute
      key: node.kubernetes.io/not-ready
      operator: Exists
      tolerationSeconds: 300
    - effect: NoExecute
      key: node.kubernetes.io/unreachable
      operator: Exists
      tolerationSeconds: 300
  volumes:
    - configMap:
        defaultMode: 420
        name: kube-dns
        optional: true
      name: kube-dns-config
    - name: kube-dns-token-lwn8l
      secret:
        defaultMode: 420
        secretName: kube-dns-token-lwn8l
status:
  conditions:
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T17:03:48Z
      status: "True"
      type: Initialized
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T17:04:05Z
      status: "True"
      type: Ready
    - lastProbeTime: null
      lastTransitionTime: null
      status: "True"
      type: ContainersReady
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T17:03:48Z
      status: "True"
      type: PodScheduled
  containerStatuses:
    - containerID: docker://10899d75b6d3925e381c0afb9092df373b81a605792b393cd40214e1e3bdf21f
      image: k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64@sha256:45df3e8e0c551bd0c79cdba48ae6677f817971dcbd1eeed7fd1f9a35118410e4
      lastState: {}
      name: dnsmasq
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:03:53Z
    - containerID: docker://147159ab40e6a10f5809340804d5486c1de1a9f2f7229e12d13241b4e675f25e
      image: k8s.gcr.io/k8s-dns-kube-dns-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-kube-dns-amd64@sha256:618a82fa66cf0c75e4753369a6999032372be7308866fc9afb381789b1e5ad52
      lastState: {}
      name: kubedns
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:03:51Z
    - containerID: docker://1624d28d50b86620f3906475c83b413f5b508bd8df3c91152f19c57baced3071
      image: gcr.io/google-containers/prometheus-to-sd:v0.2.3
      imageID: docker-pullable://gcr.io/google-containers/prometheus-to-sd@sha256:be220ec4a66275442f11d420033c106bb3502a3217a99c806eef3cf9858788a2
      lastState: {}
      name: prometheus-to-sd
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:03:58Z
    - containerID: docker://2d31545ad37c29064c2727804ab248515013114230a7a07c11956a3f22225a46
      image: k8s.gcr.io/k8s-dns-sidecar-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-sidecar-amd64@sha256:cedc8fe2098dffc26d17f64061296b7aa54258a31513b6c52df271a98bb522b3
      lastState: {}
      name: sidecar
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:03:55Z
  hostIP: 10.128.0.4
  phase: Running
  podIP: 10.40.0.5
  qosClass: Burstable
  startTime: 2018-12-03T17:03:48Z
---
apiVersion: v1
kind: Pod
metadata:
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ""
    seccomp.security.alpha.kubernetes.io/pod: docker/default
  creationTimestamp: 2018-12-03T16:59:57Z
  generateName: kube-dns-548976df6c-
  labels:
    k8s-app: kube-dns
    pod-template-hash: "456"
  name: kube-dns-548976df6c-d9kkv
  #namespace: kube-system
  ownerReferences:
    - apiVersion: apps/v1
      blockOwnerDeletion: true
      controller: true
      kind: ReplicaSet
      name: kube-dns-548976df6c
      uid: b589a851-f71b-11e8-af4f-42010a800072
  resourceVersion: "50572715"
  selfLink: /api/v1/namespaces/kube-system/pods/kube-dns-548976df6c-d9kkv
  uid: dd4bbbd4-f71c-11e8-af4f-42010a800072
spec:
  containers:
    - args:
        - --domain=cluster.local.
        - --dns-port=10053
        - --config-dir=/kube-dns-config
        - --v=2
      env:
        - name: PROMETHEUS_PORT
          value: "10055"
      image: k8s.gcr.io/k8s-dns-kube-dns-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /healthcheck/kubedns
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: kubedns
      ports:
        - containerPort: 10053
          name: dns-local
          protocol: UDP
        - containerPort: 10053
          name: dns-tcp-local
          protocol: TCP
        - containerPort: 10055
          name: metrics
          protocol: TCP
      readinessProbe:
        failureThreshold: 3
        httpGet:
          path: /readiness
          port: 8081
          scheme: HTTP
        initialDelaySeconds: 3
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      resources:
        limits:
          memory: 170Mi
        requests:
          cpu: 100m
          memory: 70Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /kube-dns-config
          name: kube-dns-config
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - args:
        - -v=2
        - -logtostderr
        - -configDir=/etc/k8s/dns/dnsmasq-nanny
        - -restartDnsmasq=true
        - --
        - -k
        - --cache-size=1000
        - --no-negcache
        - --log-facility=-
        - --server=/cluster.local/127.0.0.1#10053
        - --server=/in-addr.arpa/127.0.0.1#10053
        - --server=/ip6.arpa/127.0.0.1#10053
      image: k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /healthcheck/dnsmasq
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: dnsmasq
      ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
      resources:
        requests:
          cpu: 150m
          memory: 20Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /etc/k8s/dns/dnsmasq-nanny
          name: kube-dns-config
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - args:
        - --v=2
        - --logtostderr
        - --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
        - --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
      image: k8s.gcr.io/k8s-dns-sidecar-amd64:1.14.13
      imagePullPolicy: IfNotPresent
      livenessProbe:
        failureThreshold: 5
        httpGet:
          path: /metrics
          port: 10054
          scheme: HTTP
        initialDelaySeconds: 60
        periodSeconds: 10
        successThreshold: 1
        timeoutSeconds: 5
      name: sidecar
      ports:
        - containerPort: 10054
          name: metrics
          protocol: TCP
      resources:
        requests:
          cpu: 10m
          memory: 20Mi
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
    - command:
        - /monitor
        - --component=kubedns
        - --target-port=10054
        - --stackdriver-prefix=container.googleapis.com/internal/addons
        - --api-override=https://monitoring.googleapis.com/
        - --whitelisted-metrics=probe_kubedns_latency_ms,probe_kubedns_errors,dnsmasq_misses,dnsmasq_hits
        - --pod-id=$(POD_NAME)
        - --namespace-id=$(POD_NAMESPACE)
        - --v=2
      env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
      image: gcr.io/google-containers/prometheus-to-sd:v0.2.3
      imagePullPolicy: IfNotPresent
      name: prometheus-to-sd
      resources: {}
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
        - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          name: kube-dns-token-lwn8l
          readOnly: true
  dnsPolicy: Default
  nodeName: gke-istio-test-default-pool-866a0405-ftch
  priority: 2000000000
  priorityClassName: system-cluster-critical
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: kube-dns
  serviceAccountName: kube-dns
  terminationGracePeriodSeconds: 30
  tolerations:
    - key: CriticalAddonsOnly
      operator: Exists
    - effect: NoExecute
      key: node.kubernetes.io/not-ready
      operator: Exists
      tolerationSeconds: 300
    - effect: NoExecute
      key: node.kubernetes.io/unreachable
      operator: Exists
      tolerationSeconds: 300
  volumes:
    - configMap:
        defaultMode: 420
        name: kube-dns
        optional: true
      name: kube-dns-config
    - name: kube-dns-token-lwn8l
      secret:
        defaultMode: 420
        secretName: kube-dns-token-lwn8l
status:
  conditions:
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T17:00:00Z
      status: "True"
      type: Initialized
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T17:00:20Z
      status: "True"
      type: Ready
    - lastProbeTime: null
      lastTransitionTime: null
      status: "True"
      type: ContainersReady
    - lastProbeTime: null
      lastTransitionTime: 2018-12-03T16:59:57Z
      status: "True"
      type: PodScheduled
  containerStatuses:
    - containerID: docker://676f6c98bfa136315c4ccf0fe40e7a56cbf9ac85128e94310eae82f191246b3e
      image: k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64@sha256:45df3e8e0c551bd0c79cdba48ae6677f817971dcbd1eeed7fd1f9a35118410e4
      lastState: {}
      name: dnsmasq
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:00:14Z
    - containerID: docker://93fd0664e150982dad0481c5260183308a7035a2f938ec50509d586ed586a107
      image: k8s.gcr.io/k8s-dns-kube-dns-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-kube-dns-amd64@sha256:618a82fa66cf0c75e4753369a6999032372be7308866fc9afb381789b1e5ad52
      lastState: {}
      name: kubedns
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:00:10Z
    - containerID: docker://e823b79a0a48af75f2eebb1c89ba4c31e8c1ee67ee0d917ac7b4891b67d2cd0f
      image: gcr.io/google-containers/prometheus-to-sd:v0.2.3
      imageID: docker-pullable://gcr.io/google-containers/prometheus-to-sd@sha256:be220ec4a66275442f11d420033c106bb3502a3217a99c806eef3cf9858788a2
      lastState: {}
      name: prometheus-to-sd
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:00:18Z
    - containerID: docker://74223c401a8dac04b8bd29cdfedcb216881791b4e84bb80a15714991dd18735e
      image: k8s.gcr.io/k8s-dns-sidecar-amd64:1.14.13
      imageID: docker-pullable://k8s.gcr.io/k8s-dns-sidecar-amd64@sha256:cedc8fe2098dffc26d17f64061296b7aa54258a31513b6c52df271a98bb522b3
      lastState: {}
      name: sidecar
      ready: true
      restartCount: 0
      state:
        running:
          startedAt: 2018-12-03T17:00:16Z
  hostIP: 10.128.0.5
  phase: Running
  podIP: 10.40.1.4
  qosClass: Burstable
  startTime: 2018-12-03T17:00:00Z
---
apiVersion: v1
kind: Service
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Service","metadata":{"annotations":{},"labels":{"addonmanager.kubernetes.io/mode":"Reconcile","k8s-app":"kube-dns","kubernetes.io/cluster-service":"true","kubernetes.io/name":"KubeDNS"},"name":"kube-dns","namespace":"kube-system"},"spec":{"clusterIP":"10.43.240.10","ports":[{"name":"dns","port":53,"protocol":"UDP"},{"name":"dns-tcp","port":53,"protocol":"TCP"}],"selector":{"k8s-app":"kube-dns"}}}
  creationTimestamp: 2018-02-12T15:48:44Z
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: KubeDNS
  name: kube-dns
  #namespace: kube-system
  resourceVersion: "274"
  selfLink: /api/v1/namespaces/kube-system/services/kube-dns
  uid: 3497d702-100c-11e8-a600-42010a8002c3
spec:
  clusterIP: 10.43.240.10
  ports:
    - name: dns
      port: 53
      protocol: UDP
      targetPort: 53
    - name: dns-tcp
      port: 53
      protocol: TCP
      targetPort: 53
  selector:
    k8s-app: kube-dns
  sessionAffinity: None
  type: ClusterIP
status:
  loadBalancer: {}
---
apiVersion: v1
kind: Endpoints
metadata:
  creationTimestamp: 2018-02-12T15:48:44Z
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: KubeDNS
  name: kube-dns
  #namespace: kube-system
  resourceVersion: "50573380"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-dns
  uid: 34991433-100c-11e8-a600-42010a8002c3
subsets:
  - addresses:
      - ip: 10.40.0.5
        nodeName: gke-istio-test-default-pool-866a0405-420r
        targetRef:
          kind: Pod
          name: kube-dns-548976df6c-kxnhb
          #namespace: kube-system
          resourceVersion: "50573379"
          uid: 66b0ca7d-f71d-11e8-af4f-42010a800072
      - ip: 10.40.1.4
        nodeName: gke-istio-test-default-pool-866a0405-ftch
        targetRef:
          kind: Pod
          name: kube-dns-548976df6c-d9kkv
          #namespace: kube-system
          resourceVersion: "50572715"
          uid: dd4bbbd4-f71c-11e8-af4f-42010a800072
    ports:
      - name: dns
        port: 53
        protocol: UDP
      - name: dns-tcp
        port: 53
        protocol: TCP
`)

func datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYamlBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYaml, nil
}

func datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYaml() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJson = []byte(`{
  "istio/networking/v1alpha3/synthetic/serviceentries": []
}
`)

func datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJsonBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJson, nil
}

func datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJson() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3VirtualserviceYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
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

func datasetNetworkingIstioIoV1alpha3VirtualserviceYamlBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3VirtualserviceYaml, nil
}

func datasetNetworkingIstioIoV1alpha3VirtualserviceYaml() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3VirtualserviceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/virtualService.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYaml = []byte(`apiVersion: networking.istio.io/v1alpha3
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
          unsupportedExtraParam: true
        weight: 75
      - destination:
          host: c
          subset: v2
        weight: 25
        unsupportedExtraParam: true
`)

func datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYamlBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYaml, nil
}

func datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYaml() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJson = []byte(`{
  "istio/networking/v1alpha3/virtualservices": [
    {
      "Metadata": {
        "name": "{{.Namespace}}/valid-virtual-service"
      },
      "Body": {
        "hosts": [
          "c"
        ],
        "http": [
          {
            "route": [
              {
                "destination": {
                  "host": "c",
                  "subset": "v1"
                },
                "weight": 75
              },
              {
                "destination": {
                  "host": "c",
                  "subset": "v2"
                },
                "weight": 25
              }
            ]
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
    }
  ]
}
`)

func datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJsonBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJson, nil
}

func datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJson() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJson = []byte(`{
  "istio/networking/v1alpha3/virtualservices": [
    {
      "Metadata": {
        "name": "{{.Namespace}}/valid-virtual-service"
      },
      "Body": {
        "hosts": [
          "c"
        ],
        "http": [
          {
            "route": [
              {
                "destination": {
                  "host": "c",
                  "subset": "v1"
                },
                "weight": 75
              },
              {
                "destination": {
                  "host": "c",
                  "subset": "v2"
                },
                "weight": 25
              }
            ]
          }
        ]
      },
      "TypeURL": "type.googleapis.com/istio.networking.v1alpha3.VirtualService"
    }
  ]
}
`)

func datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJsonBytes() ([]byte, error) {
	return _datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJson, nil
}

func datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJson() (*asset, error) {
	bytes, err := datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "dataset/networking.istio.io/v1alpha3/virtualService_expected.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
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
	"dataset/config.istio.io/v1alpha2/rule.yaml":                                       datasetConfigIstioIoV1alpha2RuleYaml,
	"dataset/config.istio.io/v1alpha2/rule_expected.json":                              datasetConfigIstioIoV1alpha2Rule_expectedJson,
	"dataset/core/v1/namespace.yaml":                                                   datasetCoreV1NamespaceYaml,
	"dataset/core/v1/namespace_expected.json":                                          datasetCoreV1Namespace_expectedJson,
	"dataset/core/v1/service.yaml":                                                     datasetCoreV1ServiceYaml,
	"dataset/core/v1/service_expected.json":                                            datasetCoreV1Service_expectedJson,
	"dataset/extensions/v1beta1/ingress_basic.yaml":                                    datasetExtensionsV1beta1Ingress_basicYaml,
	"dataset/extensions/v1beta1/ingress_basic_expected.json":                           datasetExtensionsV1beta1Ingress_basic_expectedJson,
	"dataset/extensions/v1beta1/ingress_basic_meshconfig.yaml":                         datasetExtensionsV1beta1Ingress_basic_meshconfigYaml,
	"dataset/extensions/v1beta1/ingress_merge_0.yaml":                                  datasetExtensionsV1beta1Ingress_merge_0Yaml,
	"dataset/extensions/v1beta1/ingress_merge_0_expected.json":                         datasetExtensionsV1beta1Ingress_merge_0_expectedJson,
	"dataset/extensions/v1beta1/ingress_merge_0_meshconfig.yaml":                       datasetExtensionsV1beta1Ingress_merge_0_meshconfigYaml,
	"dataset/extensions/v1beta1/ingress_merge_1.yaml":                                  datasetExtensionsV1beta1Ingress_merge_1Yaml,
	"dataset/extensions/v1beta1/ingress_merge_1_expected.json":                         datasetExtensionsV1beta1Ingress_merge_1_expectedJson,
	"dataset/extensions/v1beta1/ingress_multihost.yaml":                                datasetExtensionsV1beta1Ingress_multihostYaml,
	"dataset/extensions/v1beta1/ingress_multihost_expected.json":                       datasetExtensionsV1beta1Ingress_multihost_expectedJson,
	"dataset/extensions/v1beta1/ingress_multihost_meshconfig.yaml":                     datasetExtensionsV1beta1Ingress_multihost_meshconfigYaml,
	"dataset/mesh.istio.io/v1alpha1/meshconfig.yaml":                                   datasetMeshIstioIoV1alpha1MeshconfigYaml,
	"dataset/mesh.istio.io/v1alpha1/meshconfig_expected.json":                          datasetMeshIstioIoV1alpha1Meshconfig_expectedJson,
	"dataset/networking.istio.io/v1alpha3/destinationRule.yaml":                        datasetNetworkingIstioIoV1alpha3DestinationruleYaml,
	"dataset/networking.istio.io/v1alpha3/destinationRule_expected.json":               datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJson,
	"dataset/networking.istio.io/v1alpha3/gateway.yaml":                                datasetNetworkingIstioIoV1alpha3GatewayYaml,
	"dataset/networking.istio.io/v1alpha3/gateway_expected.json":                       datasetNetworkingIstioIoV1alpha3Gateway_expectedJson,
	"dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry.yaml":                 datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYaml,
	"dataset/networking.istio.io/v1alpha3/synthetic/serviceEntry_expected.json":        datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJson,
	"dataset/networking.istio.io/v1alpha3/virtualService.yaml":                         datasetNetworkingIstioIoV1alpha3VirtualserviceYaml,
	"dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported.yaml":          datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYaml,
	"dataset/networking.istio.io/v1alpha3/virtualServiceWithUnsupported_expected.json": datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJson,
	"dataset/networking.istio.io/v1alpha3/virtualService_expected.json":                datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJson,
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
	"dataset": &bintree{nil, map[string]*bintree{
		"config.istio.io": &bintree{nil, map[string]*bintree{
			"v1alpha2": &bintree{nil, map[string]*bintree{
				"rule.yaml":          &bintree{datasetConfigIstioIoV1alpha2RuleYaml, map[string]*bintree{}},
				"rule_expected.json": &bintree{datasetConfigIstioIoV1alpha2Rule_expectedJson, map[string]*bintree{}},
			}},
		}},
		"core": &bintree{nil, map[string]*bintree{
			"v1": &bintree{nil, map[string]*bintree{
				"namespace.yaml":          &bintree{datasetCoreV1NamespaceYaml, map[string]*bintree{}},
				"namespace_expected.json": &bintree{datasetCoreV1Namespace_expectedJson, map[string]*bintree{}},
				"service.yaml":            &bintree{datasetCoreV1ServiceYaml, map[string]*bintree{}},
				"service_expected.json":   &bintree{datasetCoreV1Service_expectedJson, map[string]*bintree{}},
			}},
		}},
		"extensions": &bintree{nil, map[string]*bintree{
			"v1beta1": &bintree{nil, map[string]*bintree{
				"ingress_basic.yaml":                &bintree{datasetExtensionsV1beta1Ingress_basicYaml, map[string]*bintree{}},
				"ingress_basic_expected.json":       &bintree{datasetExtensionsV1beta1Ingress_basic_expectedJson, map[string]*bintree{}},
				"ingress_basic_meshconfig.yaml":     &bintree{datasetExtensionsV1beta1Ingress_basic_meshconfigYaml, map[string]*bintree{}},
				"ingress_merge_0.yaml":              &bintree{datasetExtensionsV1beta1Ingress_merge_0Yaml, map[string]*bintree{}},
				"ingress_merge_0_expected.json":     &bintree{datasetExtensionsV1beta1Ingress_merge_0_expectedJson, map[string]*bintree{}},
				"ingress_merge_0_meshconfig.yaml":   &bintree{datasetExtensionsV1beta1Ingress_merge_0_meshconfigYaml, map[string]*bintree{}},
				"ingress_merge_1.yaml":              &bintree{datasetExtensionsV1beta1Ingress_merge_1Yaml, map[string]*bintree{}},
				"ingress_merge_1_expected.json":     &bintree{datasetExtensionsV1beta1Ingress_merge_1_expectedJson, map[string]*bintree{}},
				"ingress_multihost.yaml":            &bintree{datasetExtensionsV1beta1Ingress_multihostYaml, map[string]*bintree{}},
				"ingress_multihost_expected.json":   &bintree{datasetExtensionsV1beta1Ingress_multihost_expectedJson, map[string]*bintree{}},
				"ingress_multihost_meshconfig.yaml": &bintree{datasetExtensionsV1beta1Ingress_multihost_meshconfigYaml, map[string]*bintree{}},
			}},
		}},
		"mesh.istio.io": &bintree{nil, map[string]*bintree{
			"v1alpha1": &bintree{nil, map[string]*bintree{
				"meshconfig.yaml":          &bintree{datasetMeshIstioIoV1alpha1MeshconfigYaml, map[string]*bintree{}},
				"meshconfig_expected.json": &bintree{datasetMeshIstioIoV1alpha1Meshconfig_expectedJson, map[string]*bintree{}},
			}},
		}},
		"networking.istio.io": &bintree{nil, map[string]*bintree{
			"v1alpha3": &bintree{nil, map[string]*bintree{
				"destinationRule.yaml":          &bintree{datasetNetworkingIstioIoV1alpha3DestinationruleYaml, map[string]*bintree{}},
				"destinationRule_expected.json": &bintree{datasetNetworkingIstioIoV1alpha3Destinationrule_expectedJson, map[string]*bintree{}},
				"gateway.yaml":                  &bintree{datasetNetworkingIstioIoV1alpha3GatewayYaml, map[string]*bintree{}},
				"gateway_expected.json":         &bintree{datasetNetworkingIstioIoV1alpha3Gateway_expectedJson, map[string]*bintree{}},
				"synthetic": &bintree{nil, map[string]*bintree{
					"serviceEntry.yaml":          &bintree{datasetNetworkingIstioIoV1alpha3SyntheticServiceentryYaml, map[string]*bintree{}},
					"serviceEntry_expected.json": &bintree{datasetNetworkingIstioIoV1alpha3SyntheticServiceentry_expectedJson, map[string]*bintree{}},
				}},
				"virtualService.yaml":                         &bintree{datasetNetworkingIstioIoV1alpha3VirtualserviceYaml, map[string]*bintree{}},
				"virtualServiceWithUnsupported.yaml":          &bintree{datasetNetworkingIstioIoV1alpha3VirtualservicewithunsupportedYaml, map[string]*bintree{}},
				"virtualServiceWithUnsupported_expected.json": &bintree{datasetNetworkingIstioIoV1alpha3Virtualservicewithunsupported_expectedJson, map[string]*bintree{}},
				"virtualService_expected.json":                &bintree{datasetNetworkingIstioIoV1alpha3Virtualservice_expectedJson, map[string]*bintree{}},
			}},
		}},
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
