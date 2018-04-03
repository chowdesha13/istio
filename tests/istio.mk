# Test-specific targets, included from top Makefile
ifeq (${TEST_ENV},minikube)

# In minikube env we don't need to push the images to dockerhub or gcr, it is all local,
# but we need to use the minikube's docker env.
# Note that tests simply use go/out, so going up 3 dirs from the os/arch/debug path
export KUBECONFIG=${GO_TOP}/out/minikube.conf
export TEST_ENV=minikube
MINIKUBE_FLAGS=--use_local_cluster --cluster_wide
.PHONY: minikube

# Prepare minikube
minikube:
	minikube update-context
	@echo "Minikube started ${KUBECONFIG}"
	minikube docker-env > ${ISTIO_OUT}/minikube.dockerenv

e2e_docker: minikube docker

else ifeq (${TEST_ENV},minikube-none)

# In minikube env we don't need to push the images to dockerhub or gcr, it is all local,
# but we need to use the minikube's docker env.
# Note that tests simply use go/out, so going up 3 dirs from the os/arch/debug path
export KUBECONFIG=${GO_TOP}/out/minikube.conf
export TEST_ENV=minikube-none
MINIKUBE_FLAGS=--use_local_cluster --cluster_wide
.PHONY: minikube

# Prepare minikube
minikube:
	minikube update-context
	@echo "Minikube started ${KUBECONFIG}"

e2e_docker: minikube docker


else

# All other test environments require the docker images to be pushed to a repo.
# The HUB is defined in user-specific .istiorc, TAG can be set or defaults to git version
e2e_docker: push

endif

# If set outside, it appears it is not possible to modify the variable.
E2E_ARGS ?=

DEFAULT_EXTRA_E2E_ARGS = ${MINIKUBE_FLAGS}
DEFAULT_EXTRA_E2E_ARGS += --istioctl=${ISTIO_OUT}/istioctl
DEFAULT_EXTRA_E2E_ARGS += --mixer_tag=${TAG}
DEFAULT_EXTRA_E2E_ARGS += --pilot_tag=${TAG}
DEFAULT_EXTRA_E2E_ARGS += --proxy_tag=${TAG}
DEFAULT_EXTRA_E2E_ARGS += --ca_tag=${TAG}
DEFAULT_EXTRA_E2E_ARGS += --mixer_hub=${HUB}
DEFAULT_EXTRA_E2E_ARGS += --pilot_hub=${HUB}
DEFAULT_EXTRA_E2E_ARGS += --proxy_hub=${HUB}
DEFAULT_EXTRA_E2E_ARGS += --ca_hub=${HUB}

EXTRA_E2E_ARGS ?= ${DEFAULT_EXTRA_E2E_ARGS}

# These arguments are only needed by upgrade test.
DEFAULT_UPGRADE_E2E_ARGS =
LAST_RELEASE := $(shell curl -L -s https://api.github.com/repos/istio/istio/releases/latest \
	| grep tag_name | sed "s/ *\"tag_name\": *\"\(.*\)\",*/\1/")
DEFAULT_UPGRADE_E2E_ARGS += --base_version=${LAST_RELEASE}
DEFAULT_UPGRADE_E2E_ARGS += --target_version=""
UPGRADE_E2E_ARGS ?= ${DEFAULT_UPGRADE_E2E_ARGS}

# Simple e2e test using fortio, approx 2 min
e2e_simple: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/simple -args ${E2E_ARGS} ${EXTRA_E2E_ARGS}

e2e_simple_run:
	go test -v -timeout 20m ./tests/e2e/tests/simple -args ${E2E_ARGS} ${EXTRA_E2E_ARGS}

e2e_mixer: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/mixer -args ${E2E_ARGS} ${EXTRA_E2E_ARGS}

e2e_dashboard: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/dashboard -args ${E2E_ARGS} ${EXTRA_E2E_ARGS}

e2e_bookinfo: istioctl generate_yaml
	go test -v -timeout 60m ./tests/e2e/tests/bookinfo -args ${E2E_ARGS} ${EXTRA_E2E_ARGS}

e2e_upgrade: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/upgrade -args ${E2E_ARGS} ${EXTRA_E2E_ARGS} ${UPGRADE_E2E_ARGS}

e2e_version_skew: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/upgrade -args --smooth_check=true ${E2E_ARGS} ${EXTRA_E2E_ARGS} ${UPGRADE_E2E_ARGS}

e2e_all:
	$(MAKE) --keep-going e2e_simple e2e_mixer e2e_bookinfo e2e_dashboard e2e_upgrade

JUNIT_E2E_XML ?= $(ISTIO_OUT)/junit_e2e-all.xml
e2e_all_junit_report: | $(JUNIT_REPORT)
	mkdir -p $(dir $(JUNIT_E2E_XML))
	set -o pipefail; $(MAKE) e2e_all 2>&1 | tee >($(JUNIT_REPORT) > $(JUNIT_E2E_XML))

# The pilot tests cannot currently be part of e2e_all, since they requires some additional flags.
e2e_pilot: istioctl generate_yaml
	go test -v -timeout 20m ./tests/e2e/tests/pilot ${E2E_ARGS} ${EXTRA_E2E_ARGS}

test/minikube/auth/e2e_simple:
	set -o pipefail; go test -v -timeout 20m ./tests/e2e/tests/simple -args --auth_enable=true \
	  --skip_cleanup  -use_local_cluster -cluster_wide -test.v \
	  ${E2E_ARGS} ${EXTRA_E2E_ARGS} \
           ${TESTOPTS} | tee ${OUT_DIR}/tests/test-report-auth-simple.raw

test/minikube/noauth/e2e_simple:
	mkdir -p ${OUT_DIR}/tests
	set -o pipefail; go test -v -timeout 20m ./tests/e2e/tests/simple -args --auth_enable=false \
	  --skip_cleanup  -use_local_cluster -cluster_wide -test.v \
	  ${E2E_ARGS} ${EXTRA_E2E_ARGS} \
           ${TESTOPTS} | tee ${OUT_DIR}/tests/test-report-noauth-simple.raw
