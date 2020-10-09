// Copyright Istio Authors
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

package security

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"

	"istio.io/istio/pkg/config/host"
)

// JwksInfo provides values resulting from parsing a jwks URI.
type JwksInfo struct {
	Hostname host.Name
	Scheme   string
	Port     int
	UseSSL   bool
}

const (
	attrRequestHeader    = "request.headers"        // header name is surrounded by brackets, e.g. "request.headers[User-Agent]".
	attrSrcIP            = "source.ip"              // supports both single ip and cidr, e.g. "10.1.2.3" or "10.1.0.0/16".
	attrSrcNamespace     = "source.namespace"       // e.g. "default".
	attrSrcPrincipal     = "source.principal"       // source identity, e,g, "cluster.local/ns/default/sa/productpage".
	attrRequestPrincipal = "request.auth.principal" // authenticated principal of the request.
	attrRequestAudiences = "request.auth.audiences" // intended audience(s) for this authentication information.
	attrRequestPresenter = "request.auth.presenter" // authorized presenter of the credential.
	attrRequestClaims    = "request.auth.claims"    // claim name is surrounded by brackets, e.g. "request.auth.claims[iss]".
	attrDestIP           = "destination.ip"         // supports both single ip and cidr, e.g. "10.1.2.3" or "10.1.0.0/16".
	attrDestPort         = "destination.port"       // must be in the range [0, 65535].
	attrDestLabel        = "destination.labels"     // label name is surrounded by brackets, e.g. "destination.labels[version]".
	attrDestName         = "destination.name"       // short service name, e.g. "productpage".
	attrDestNamespace    = "destination.namespace"  // e.g. "default".
	attrDestUser         = "destination.user"       // service account, e.g. "bookinfo-productpage".
	attrConnSNI          = "connection.sni"         // server name indication, e.g. "www.example.com".
	attrExperimental     = "experimental.envoy.filters."
)

// ParseJwksURI parses the input URI and returns the corresponding hostname, port, and whether SSL is used.
// URI must start with "http://" or "https://", which corresponding to "http" or "https" scheme.
// Port number is extracted from URI if available (i.e from postfix :<port>, eg. ":80"), or assigned
// to a default value based on URI scheme (80 for http and 443 for https).
// Port name is set to URI scheme value.
func ParseJwksURI(jwksURI string) (JwksInfo, error) {
	u, err := url.Parse(jwksURI)
	if err != nil {
		return JwksInfo{}, err
	}
	info := JwksInfo{}
	switch u.Scheme {
	case "http":
		info.UseSSL = false
		info.Port = 80
	case "https":
		info.UseSSL = true
		info.Port = 443
	default:
		return JwksInfo{}, fmt.Errorf("URI scheme %q is not supported", u.Scheme)
	}

	if u.Port() != "" {
		info.Port, err = strconv.Atoi(u.Port())
		if err != nil {
			return JwksInfo{}, err
		}
	}
	info.Hostname = host.Name(u.Hostname())
	info.Scheme = u.Scheme

	return info, nil
}

func CheckEmptyValues(key string, values []string) error {
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("empty value not allowed, found in %s", key)
		}
	}
	return nil
}

func ValidateAttribute(key string, values []string) error {
	if err := CheckEmptyValues(key, values); err != nil {
		return err
	}
	switch {
	case hasPrefix(key, attrRequestHeader):
		return validateMapKey(key)
	case isEqual(key, attrSrcIP):
		return ValidateIPs(values)
	case isEqual(key, attrSrcNamespace):
	case isEqual(key, attrSrcPrincipal):
	case isEqual(key, attrRequestPrincipal):
	case isEqual(key, attrRequestAudiences):
	case isEqual(key, attrRequestPresenter):
	case hasPrefix(key, attrRequestClaims):
		return validateMapKey(key)
	case isEqual(key, attrDestIP):
		return ValidateIPs(values)
	case isEqual(key, attrDestPort):
		return ValidatePorts(values)
	case isEqual(key, attrConnSNI):
	case hasPrefix(key, attrExperimental):
		return validateMapKey(key)
	case isEqual(key, attrDestNamespace):
		return fmt.Errorf("attribute %s is replaced by the metadata.namespace", key)
	case hasPrefix(key, attrDestLabel):
		return fmt.Errorf("attribute %s is replaced by the workload selector", key)
	case isEqual(key, attrDestName, attrDestUser):
		return fmt.Errorf("deprecated attribute %s: only supported in v1alpha1", key)
	default:
		return fmt.Errorf("unknown attribute: %s", key)
	}
	return nil
}

func isEqual(key string, values ...string) bool {
	for _, v := range values {
		if key == v {
			return true
		}
	}
	return false
}

func hasPrefix(key string, prefix string) bool {
	return strings.HasPrefix(key, prefix)
}

func ValidateIPs(ips []string) error {
	var errs *multierror.Error
	for _, v := range ips {
		if strings.Contains(v, "/") {
			if _, _, err := net.ParseCIDR(v); err != nil {
				errs = multierror.Append(errs, fmt.Errorf("bad CIDR range (%s): %v", v, err))
			}
		} else {
			if ip := net.ParseIP(v); ip == nil {
				errs = multierror.Append(errs, fmt.Errorf("bad IP address (%s)", v))
			}
		}
	}
	return errs.ErrorOrNil()
}

func ValidatePorts(ports []string) error {
	var errs *multierror.Error
	for _, port := range ports {
		p, err := strconv.ParseUint(port, 10, 32)
		if err != nil || p > 65535 {
			errs = multierror.Append(errs, fmt.Errorf("bad port (%s): %v", port, err))
		}
	}
	return errs.ErrorOrNil()
}

func validateMapKey(key string) error {
	open := strings.Index(key, "[")
	if strings.HasSuffix(key, "]") && open > 0 && open < len(key)-2 {
		return nil
	}
	return fmt.Errorf("bad key (%s): should have format a[b]", key)
}

func ValidateServer(server string, isTCP bool) error {
	u, err := url.Parse(server)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "grpc":
	case "http", "https":
		if isTCP {
			return fmt.Errorf("scheme for TCP filter chain must be grpc, found %s", u.Scheme)
		}
	default:
		return fmt.Errorf("scheme for HTTP filter chain must be http, https or grpc, found %s", u.Scheme)
	}
	if u.Fragment != "" {
		return fmt.Errorf("must not include fragment, found %s", u.Fragment)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("must not include query, found %s", u.RawQuery)
	}
	return nil
}
