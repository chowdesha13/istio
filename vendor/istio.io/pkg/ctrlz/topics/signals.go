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

package topics

import (
	"fmt"
	"html/template"
	"net/http"
	"syscall"

	"istio.io/pkg/appsignals"
	"istio.io/pkg/ctrlz/fw"
	"istio.io/pkg/ctrlz/topics/assets"
)

type signalsTopic struct {
}

// SignalsTopic returns a ControlZ topic that sends command signals to the process
func SignalsTopic() fw.Topic {
	return signalsTopic{}
}

func (signalsTopic) Title() string {
	return "Signals"
}

func (signalsTopic) Prefix() string {
	return "signal"
}

func (signalsTopic) Activate(context fw.TopicContext) {
	tmpl := template.Must(context.Layout().Parse(string(assets.MustAsset("templates/signals.html"))))

	_ = context.HTMLRouter().StrictSlash(true).NewRoute().Path("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fw.RenderHTML(w, tmpl, nil)
	})

	_ = context.JSONRouter().StrictSlash(true).NewRoute().Methods("PUT", "POST").Path("/SIGUSR1").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		appsignals.Notify(fmt.Sprintf("Remote: %v", req.RemoteAddr), syscall.SIGUSR1)
		w.WriteHeader(http.StatusAccepted)
	})
}
