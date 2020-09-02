package istioagent

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type HealthCheckType string

const (
	HTTPHealthCheck   HealthCheckType = "HTTP"
	TCPHealthCheck    HealthCheckType = "TCP"
	ExecHealthCheck   HealthCheckType = "Exec"
	HealthInfoTypeUrl string          = "type.googleapis.com/istio.v1.HealthInformation"
)

type WorkloadHealthChecker struct {
	config ApplicationHealthCheckConfig
}

type ApplicationHealthCheckConfig struct {
	InitialDelay   time.Duration
	ProbeTimeout   time.Duration
	CheckFrequency time.Duration
	SuccessThresh  int
	FailThresh     int
	CheckType      HealthCheckType
	HTTPConfig     HTTPHealthCheckConfig
	TCPConfig      TCPHealthCheckConfig
	ExecConfig     ExecHealthCheckConfig
}

type HTTPHealthCheckConfig struct {
	Path    string
	Port    uint32
	Scheme  string
	Headers map[string]string
}

type TCPHealthCheckConfig struct {
	Host string
	Port string
}

type ExecHealthCheckConfig struct {
	ExecutableName string
	Args           []string
}

// PerformApplicationHealthCheck Performs the application-provided configuration health check.
// Designed to run async.
// TODO:
// 	- Add channel param for quit (better error handling as well)
// 	- Because there are 3 possible configs, there are 3 possible healthcheck paths, and all of them
// 		are defined here. Therefore, there is quite a bit of duplicate code in success/fail threshold
// 		and healthChannel sending. This code should be better.
// 	- Should the CheckFrequency Delay be a time.Ticker?
func (w *WorkloadHealthChecker) PerformApplicationHealthCheck(notifyHealthChange chan *discovery.DiscoveryRequest) {
	// delay before starting probes.
	time.Sleep(w.config.InitialDelay)

	numSuccess, numFail := 0, 0
	if w.config.CheckType == HTTPHealthCheck {
		for {
			if code, err := httpCheck(w.config.HTTPConfig, w.config.ProbeTimeout); code >= 200 && code <= 299 {
				numSuccess++
				if numSuccess == w.config.SuccessThresh {
					notifyHealthChange <- &discovery.DiscoveryRequest{TypeUrl: HealthInfoTypeUrl}
					numSuccess = 0
				}
			} else {
				numFail++
				if numFail == w.config.FailThresh {
					notifyHealthChange <- &discovery.DiscoveryRequest{
						TypeUrl: HealthInfoTypeUrl,
						ErrorDetail: &status.Status{
							Code:    int32(code),
							Message: err.Error(),
						},
					}
					numFail = 0
				}
			}
			// should this be a time.Ticker?
			time.Sleep(w.config.CheckFrequency)
		}
	}

	if w.config.CheckType == TCPHealthCheck {
		for {
			if err := tcpCheck(w.config.TCPConfig, w.config.ProbeTimeout); err == nil {
				numSuccess++
				if numSuccess == w.config.SuccessThresh {
					notifyHealthChange <- &discovery.DiscoveryRequest{TypeUrl: HealthInfoTypeUrl}
					numSuccess = 0
				}
			} else {
				numFail++
				if numFail == w.config.FailThresh {
					notifyHealthChange <- &discovery.DiscoveryRequest{
						TypeUrl: HealthInfoTypeUrl,
						ErrorDetail: &status.Status{
							Code:    int32(500),
							Message: err.Error(),
						},
					}
					numFail = 0
				}
			}
		}
	}

	if w.config.CheckType == ExecHealthCheck {
		for {
			if err := execCheck(w.config.ExecConfig); err == nil {
				numSuccess++
				if numSuccess == w.config.SuccessThresh {
					notifyHealthChange <- &discovery.DiscoveryRequest{TypeUrl: HealthInfoTypeUrl}
					numSuccess = 0
				} else {
					numFail++
					if numFail == w.config.FailThresh {
						notifyHealthChange <- &discovery.DiscoveryRequest{
							TypeUrl: HealthInfoTypeUrl,
							ErrorDetail: &status.Status{
								Code:    int32(500),
								Message: err.Error(),
							},
						}
						numFail = 0
					}
				}
			}
		}
	}
}

// httpCheck performs a http get to a given endpoint with a timeout, and returns
// the status and error.
func httpCheck(config HTTPHealthCheckConfig, timeout time.Duration) (int, error) {
	client := http.Client{
		Timeout: timeout,
	}
	url := fmt.Sprintf("%s://localhost:%v/%s", config.Scheme, config.Port, config.Path)
	resp, err := client.Get(url)
	return resp.StatusCode, err
}

// tcpCheck connects to a given endpoint with a timeout, and errors
// if connecting is unavailable (unhealthy)
func tcpCheck(config TCPHealthCheckConfig, timeout time.Duration) error {
	d := net.Dialer{
		Timeout: timeout,
	}
	url := fmt.Sprintf("%s:%v", config.Host, config.Port)
	conn, err := d.Dial("tcp", url)
	if conn != nil {
		conn.Close()
	}
	return err
}

// todo does adding Stderr to exec cmd return the error there?
func execCheck(config ExecHealthCheckConfig) error {
	healthCheckCmd := &exec.Cmd{
		Path:   config.ExecutableName,
		Args:   config.Args,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
	}
	return healthCheckCmd.Run()
}

// TODO implement
func (w *WorkloadHealthChecker) PerformEnvoyHealthCheck() {

}
