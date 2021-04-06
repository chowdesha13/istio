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

package model

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"go.opencensus.io/stats/view"

	"istio.io/istio/pilot/pkg/model/test"
	"istio.io/istio/pkg/test/util/retry"
)

const testRetryInterval = time.Millisecond * 10

func TestResolveJwksURIUsingOpenID(t *testing.T) {
	r := NewJwksResolver(JwtPubKeyEvictionDuration, JwtPubKeyRefreshInterval, JwtPubKeyRefreshIntervalOnFailure, testRetryInterval)
	defer r.Close()

	ms, err := test.StartNewServer()
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	cases := []struct {
		in              string
		expectedJwksURI string
		expectedError   bool
	}{
		{
			in:              ms.URL,
			expectedJwksURI: mockCertURL,
		},
		{
			in:              ms.URL, // Send two same request, mock server is expected to hit twice.
			expectedJwksURI: mockCertURL,
		},
		{
			in:            "http://xyz",
			expectedError: true,
		},
	}
	for _, c := range cases {
		jwksURI, err := r.resolveJwksURIUsingOpenID(c.in)
		if err != nil && !c.expectedError {
			t.Errorf("resolveJwksURIUsingOpenID(%+v): got error (%v)", c.in, err)
		} else if err == nil && c.expectedError {
			t.Errorf("resolveJwksURIUsingOpenID(%+v): expected error, got no error", c.in)
		} else if c.expectedJwksURI != jwksURI {
			t.Errorf("resolveJwksURIUsingOpenID(%+v): expected (%s), got (%s)",
				c.in, c.expectedJwksURI, jwksURI)
		}
	}

	// Verify mock openID discovery http://localhost:9999/.well-known/openid-configuration was called twice.
	if got, want := ms.OpenIDHitNum, uint64(2); got != want {
		t.Errorf("Mock OpenID discovery Hit number => expected %d but got %d", want, got)
	}
}

func TestGetPublicKey(t *testing.T) {
	r := NewJwksResolver(JwtPubKeyEvictionDuration, JwtPubKeyRefreshInterval, JwtPubKeyRefreshIntervalOnFailure, testRetryInterval)
	defer r.Close()

	ms, err := test.StartNewServer()
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}

	mockCertURL := ms.URL + "/oauth2/v3/certs"

	cases := []struct {
		in                []string
		expectedJwtPubkey string
	}{
		{
			in:                []string{"testIssuer", mockCertURL},
			expectedJwtPubkey: test.JwtPubKey1,
		},
		{
			in:                []string{"testIssuer", mockCertURL}, // Send two same request, mock server is expected to hit only once because of the cache.
			expectedJwtPubkey: test.JwtPubKey1,
		},
	}
	for _, c := range cases {
		pk, err := r.GetPublicKey(c.in[0], c.in[1])
		if err != nil {
			t.Errorf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", c.in, err)
		}
		if c.expectedJwtPubkey != pk {
			t.Errorf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", c.in, c.expectedJwtPubkey, pk)
		}
	}

	// Verify mock server http://localhost:9999/oauth2/v3/certs was only called once because of the cache.
	if got, want := ms.PubKeyHitNum, uint64(1); got != want {
		t.Errorf("Mock server Hit number => expected %d but got %d", want, got)
	}
}

func TestGetPublicKeyReorderedKey(t *testing.T) {
	r := NewJwksResolver(JwtPubKeyEvictionDuration, testRetryInterval*20, testRetryInterval*10, testRetryInterval)
	defer r.Close()

	ms, err := test.StartNewServer()
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}
	ms.ReturnReorderedKeyAfterFirstNumHits = 1

	mockCertURL := ms.URL + "/oauth2/v3/certs"

	cases := []struct {
		in                []string
		expectedJwtPubkey string
	}{
		{
			in:                []string{"", mockCertURL},
			expectedJwtPubkey: test.JwtPubKey1,
		},
		{
			in:                []string{"", mockCertURL}, // Send two same request, mock server is expected to hit only once because of the cache.
			expectedJwtPubkey: test.JwtPubKey1Reordered,
		},
	}
	for _, c := range cases {
		pk, err := r.GetPublicKey(c.in[0], c.in[1])
		if err != nil {
			t.Errorf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", c.in, err)
		}
		if c.expectedJwtPubkey != pk {
			t.Errorf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", c.in, c.expectedJwtPubkey, pk)
		}
		r.refresh()
	}

	// Verify refresh job key changed count is zero.
	if got, want := r.refreshJobKeyChangedCount, uint64(0); got != want {
		t.Errorf("JWKs Resolver Refreshed Key Count => expected %d but got %d", want, got)
	}
}

func TestGetPublicKeyUsingTLS(t *testing.T) {
	r := newJwksResolverWithCABundlePaths(
		JwtPubKeyEvictionDuration,
		JwtPubKeyRefreshInterval,
		JwtPubKeyRefreshIntervalOnFailure,
		testRetryInterval,
		[]string{"./test/testcert/cert.pem"},
	)
	defer r.Close()

	ms, err := test.StartNewTLSServer("./test/testcert/cert.pem", "./test/testcert/key.pem")
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	pk, err := r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Errorf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", mockCertURL, err)
	}
	if test.JwtPubKey1 != pk {
		t.Errorf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", mockCertURL, test.JwtPubKey1, pk)
	}
}

func TestGetPublicKeyUsingTLSBadCert(t *testing.T) {
	r := newJwksResolverWithCABundlePaths(
		JwtPubKeyEvictionDuration,
		JwtPubKeyRefreshInterval,
		testRetryInterval,
		JwtPubKeyRefreshIntervalOnFailure,
		[]string{"./test/testcert/cert2.pem"},
	)
	defer r.Close()

	ms, err := test.StartNewTLSServer("./test/testcert/cert.pem", "./test/testcert/key.pem")
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	_, err = r.GetPublicKey("", mockCertURL)
	if err == nil {
		t.Errorf("GetPublicKey(\"\", %+v) did not fail: expected bad certificate error, got no error", mockCertURL)
	}
}

func TestGetPublicKeyUsingTLSWithoutCABundles(t *testing.T) {
	r := newJwksResolverWithCABundlePaths(
		JwtPubKeyEvictionDuration,
		JwtPubKeyRefreshInterval,
		testRetryInterval,
		JwtPubKeyRefreshIntervalOnFailure,
		[]string{},
	)
	defer r.Close()

	ms, err := test.StartNewTLSServer("./test/testcert/cert.pem", "./test/testcert/key.pem")
	defer ms.Stop()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	_, err = r.GetPublicKey("", mockCertURL)
	if err == nil {
		t.Errorf("GetPublicKey(\"\", %+v) did not fail: expected https unsupported error, got no error", mockCertURL)
	}
}

func TestJwtPubKeyEvictionForNotUsed(t *testing.T) {
	r := NewJwksResolver(
		100*time.Millisecond, /*EvictionDuration*/
		2*time.Millisecond,   /*RefreshInterval*/
		2*time.Millisecond,   /*RefreshIntervalOnFailure*/
		testRetryInterval,
	)
	defer r.Close()

	ms := startMockServer(t)
	defer ms.Stop()

	// Mock server returns JwtPubKey2 for later calls.
	// Verify the refresher has run and got new key from mock server.
	verifyKeyRefresh(t, r, ms, test.JwtPubKey2)

	// Wait until unused keys are evicted.
	key := jwtKey{jwksURI: ms.URL + "/oauth2/v3/certs", issuer: "istio-test"}

	retry.UntilSuccessOrFail(t, func() error {
		// Verify the public key is evicted.
		if _, found := r.keyEntries.Load(key); found {
			return fmt.Errorf("public key is not evicted")
		}
		return nil
	})
}

func TestJwtPubKeyEvictionForNotRefreshed(t *testing.T) {
	r := NewJwksResolver(
		100*time.Millisecond, /*EvictionDuration*/
		10*time.Millisecond,  /*RefreshInterval*/
		10*time.Millisecond,  /*RefreshIntervalOnFailure*/
		testRetryInterval,    /*RetryInterval*/
	)
	defer r.Close()

	ms := startMockServer(t)
	defer ms.Stop()

	// Configures the mock server to return error after the first request.
	ms.ReturnErrorAfterFirstNumHits = 1

	mockCertURL := ms.URL + "/oauth2/v3/certs"

	pk, err := r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Fatalf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", mockCertURL, err)
	}
	// Mock server returns JwtPubKey1 for first call.
	if test.JwtPubKey1 != pk {
		t.Fatalf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", mockCertURL, test.JwtPubKey1, pk)
	}

	// Keep getting the public key to change the lastUsedTime of the public key.
	done := make(chan struct{})
	go func() {
		c := time.NewTicker(10 * time.Millisecond)
		for {
			select {
			case <-done:
				return
			case <-c.C:
				_, _ = r.GetPublicKey(mockCertURL, "")
			}
		}
	}()
	defer func() {
		done <- struct{}{}
	}()

	// Verify the cached public key is removed after failed to refresh longer than the eviction duration.
	retry.UntilSuccessOrFail(t, func() error {
		_, err = r.GetPublicKey(mockCertURL, "")
		if err == nil {
			return fmt.Errorf("getPublicKey(\"\", %+v) fails: expected error, got no error", mockCertURL)
		}
		return nil
	})
}

func TestJwtPubKeyLastRefreshedTime(t *testing.T) {
	r := NewJwksResolver(
		JwtPubKeyEvictionDuration,
		2*time.Millisecond, /*RefreshInterval*/
		2*time.Millisecond, /*RefreshIntervalOnFailure*/
		testRetryInterval,  /*RetryInterval*/
	)
	defer r.Close()

	ms := startMockServer(t)
	defer ms.Stop()

	// Mock server returns JwtPubKey2 for later calls.
	// Verify the refresher has run and got new key from mock server.
	verifyKeyRefresh(t, r, ms, test.JwtPubKey2)

	// The lastRefreshedTime should change for each successful refresh.
	verifyKeyLastRefreshedTime(t, r, ms, true /* wantChanged */)
}

func TestJwtPubKeyRefreshWithNetworkError(t *testing.T) {
	r := NewJwksResolver(
		JwtPubKeyEvictionDuration,
		time.Second, /*RefreshInterval*/
		time.Second, /*RefreshIntervalOnFailure*/
		testRetryInterval,
	)
	defer r.Close()

	ms := startMockServer(t)
	defer ms.Stop()

	// Configures the mock server to return error after the first request.
	ms.ReturnErrorAfterFirstNumHits = 1

	// The refresh job should continue using the previously fetched public key (JwtPubKey1).
	verifyKeyRefresh(t, r, ms, test.JwtPubKey1)

	// The lastRefreshedTime should not change the refresh failed due to network error.
	verifyKeyLastRefreshedTime(t, r, ms, false /* wantChanged */)
}

func TestJwtRefreshIntervalExponentialBackoff(t *testing.T) {
	defaultRefreshInterval := 50 * time.Millisecond
	refreshIntervalOnFail := 2 * time.Millisecond
	r := NewJwksResolver(JwtPubKeyEvictionDuration, defaultRefreshInterval, refreshIntervalOnFail, 1*time.Millisecond)

	ms := startMockServer(t)
	defer ms.Stop()

	// Configures the mock server to return error after the first request.
	ms.ReturnErrorAfterFirstNumHits = 1

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	_, err := r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Fatalf("GetPublicKey(%q, %+v) fails: expected no error, got (%v)", "", mockCertURL, err)
	}

	time.Sleep(100 * time.Millisecond)
	r.Close()

	powerOfTwo := func(n int64) bool {
		return n != 0 && (n&(n-1) == 0)
	}
	if r.refreshInterval == refreshIntervalOnFail || !powerOfTwo(r.refreshInterval.Milliseconds()/time.Millisecond.Milliseconds()) {
		t.Errorf("refreshInterval not updated with exponential backoff, got %v", r.refreshInterval)
	}
}

func TestJwtRefreshIntervalRecoverFromInitialFailOnFirstHit(t *testing.T) {
	defaultRefreshInterval := 50 * time.Millisecond
	refreshIntervalOnFail := 2 * time.Millisecond
	r := NewJwksResolver(JwtPubKeyEvictionDuration, defaultRefreshInterval, refreshIntervalOnFail, 1*time.Millisecond)

	ms := startMockServer(t)
	defer ms.Stop()

	// Configures the mock server to return error for the first 3 requests.
	ms.ReturnErrorForFirstNumHits = 3

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	pk, err := r.GetPublicKey("", mockCertURL)
	if err == nil {
		t.Fatalf("GetPublicKey(%q, %+v) fails: expected error, got no error: (%v)", pk, mockCertURL, err)
	}

	retry.UntilOrFail(t, func() bool {
		pk, _ := r.GetPublicKey("", mockCertURL)
		return test.JwtPubKey2 == pk
	}, retry.Delay(time.Millisecond))
	r.Close()

	i := 0
	r.keyEntries.Range(func(_ interface{}, _ interface{}) bool {
		i++
		return true
	})

	expectedEntries := 1
	if i != expectedEntries {
		t.Errorf("expected entries in cache: %d , got %d", expectedEntries, i)
	}

	if r.refreshInterval != defaultRefreshInterval {
		t.Errorf("expected refreshInterval to be refreshDefaultInterval: %v, got %v", defaultRefreshInterval, r.refreshInterval)
	}
}

func TestJwtRefreshIntervalRecoverFromFail(t *testing.T) {
	defaultRefreshInterval := 50 * time.Millisecond
	refreshIntervalOnFail := 2 * time.Millisecond
	r := NewJwksResolver(JwtPubKeyEvictionDuration, defaultRefreshInterval, refreshIntervalOnFail, 1*time.Millisecond)

	ms := startMockServer(t)
	defer ms.Stop()

	// Configures the mock server to return error after the first request.
	ms.ReturnErrorAfterFirstNumHits = 1
	ms.ReturnSuccessAfterFirstNumHits = 3

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	_, err := r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Fatalf("GetPublicKey(%q, %+v) fails: expected no error, got (%v)", "", mockCertURL, err)
	}

	retry.UntilOrFail(t, func() bool {
		pk, _ := r.GetPublicKey("", mockCertURL)
		return test.JwtPubKey1 == pk
	}, retry.Delay(time.Millisecond))
	r.Close()

	if r.refreshInterval != defaultRefreshInterval {
		t.Errorf("expected defaultRefreshInterval: %v , got %v", defaultRefreshInterval, r.refreshInterval)
	}
}

func getCounterValue(counterName string, t *testing.T) float64 {
	counterValue := 0.0
	if data, err := view.RetrieveData(counterName); err == nil {
		if len(data) != 0 {
			counterValue = data[0].Data.(*view.SumData).Value
		}
	} else {
		t.Fatalf("failed to get value for counter %s: %v", counterName, err)
	}
	return counterValue
}

func TestJwtPubKeyMetric(t *testing.T) {
	defaultRefreshInterval := 50 * time.Millisecond
	refreshIntervalOnFail := 2 * time.Millisecond
	r := NewJwksResolver(JwtPubKeyEvictionDuration, defaultRefreshInterval, refreshIntervalOnFail, 1*time.Millisecond)
	defer r.Close()

	ms := startMockServer(t)
	defer ms.Stop()

	ms.ReturnErrorForFirstNumHits = 1

	successValueBefore := getCounterValue(networkFetchSuccessCounter.Name(), t)
	failValueBefore := getCounterValue(networkFetchFailCounter.Name(), t)

	mockCertURL := ms.URL + "/oauth2/v3/certs"
	cases := []struct {
		in                []string
		expectedJwtPubkey string
	}{
		{
			in:                []string{"", mockCertURL},
			expectedJwtPubkey: "",
		},
		{
			in:                []string{"", mockCertURL},
			expectedJwtPubkey: test.JwtPubKey2,
		},
	}

	for _, c := range cases {
		retry.UntilOrFail(t, func() bool {
			pk, _ := r.GetPublicKey(c.in[0], c.in[1])
			return c.expectedJwtPubkey == pk
		}, retry.Delay(time.Millisecond))
	}

	successValueAfter := getCounterValue(networkFetchSuccessCounter.Name(), t)
	failValueAfter := getCounterValue(networkFetchFailCounter.Name(), t)
	if successValueBefore >= successValueAfter {
		t.Errorf("the success counter is not incremented")
	}
	if failValueBefore >= failValueAfter {
		t.Errorf("the fail counter is not incremented")
	}
}

func startMockServer(t *testing.T) *test.MockOpenIDDiscoveryServer {
	t.Helper()

	ms, err := test.StartNewServer()
	if err != nil {
		t.Fatal("failed to start a mock server")
	}
	return ms
}

func verifyKeyRefresh(t *testing.T, r *JwksResolver, ms *test.MockOpenIDDiscoveryServer, expectedJwtPubkey string) {
	t.Helper()
	mockCertURL := ms.URL + "/oauth2/v3/certs"

	pk, err := r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Fatalf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", mockCertURL, err)
	}
	// Mock server returns JwtPubKey1 for first call.
	if test.JwtPubKey1 != pk {
		t.Fatalf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", mockCertURL, test.JwtPubKey1, pk)
	}

	// Wait until refresh job at least finished once.
	retry.UntilSuccessOrFail(t, func() error {
		// Make sure refresh job has run and detect change or refresh happened.
		if atomic.LoadUint64(&r.refreshJobKeyChangedCount) > 0 || atomic.LoadUint64(&r.refreshJobFetchFailedCount) > 0 {
			return nil
		}
		return fmt.Errorf("refresher failed to run")
	})
	pk, err = r.GetPublicKey("", mockCertURL)
	if err != nil {
		t.Fatalf("GetPublicKey(\"\", %+v) fails: expected no error, got (%v)", mockCertURL, err)
	}
	if expectedJwtPubkey != pk {
		t.Fatalf("GetPublicKey(\"\", %+v): expected (%s), got (%s)", mockCertURL, expectedJwtPubkey, pk)
	}
}

func verifyKeyLastRefreshedTime(t *testing.T, r *JwksResolver, ms *test.MockOpenIDDiscoveryServer, wantChanged bool) {
	t.Helper()
	mockCertURL := ms.URL + "/oauth2/v3/certs"
	key := jwtKey{jwksURI: mockCertURL}

	e, found := r.keyEntries.Load(key)
	if !found {
		t.Fatalf("No cached public key for %+v", key)
	}
	oldRefreshedTime := e.(jwtPubKeyEntry).lastRefreshedTime

	time.Sleep(200 * time.Millisecond)

	e, found = r.keyEntries.Load(key)
	if !found {
		t.Fatalf("No cached public key for %+v", key)
	}
	newRefreshedTime := e.(jwtPubKeyEntry).lastRefreshedTime

	if actualChanged := oldRefreshedTime != newRefreshedTime; actualChanged != wantChanged {
		t.Errorf("Want changed: %t but got %t", wantChanged, actualChanged)
	}
}

func TestCompareJWKSResponse(t *testing.T) {
	type args struct {
		oldKeyString string
		newKeyString string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"testEquivalentStrings", args{test.JwtPubKey1, test.JwtPubKey1}, false, false},
		{"testReorderedKeys", args{test.JwtPubKey1, test.JwtPubKey1Reordered}, false, false},
		{"testDifferentKeys", args{test.JwtPubKey1, test.JwtPubKey2}, true, false},
		{"testOldJsonParseFailure", args{"This is not JSON", test.JwtPubKey1}, true, false},
		{"testNewJsonParseFailure", args{test.JwtPubKey1, "This is not JSON"}, false, true},
		{"testNewNoKid", args{test.JwtPubKey1, test.JwtPubKeyNoKid}, true, false},
		{"testOldNoKid", args{test.JwtPubKeyNoKid, test.JwtPubKey1}, true, false},
		{"testBothNoKidSame", args{test.JwtPubKeyNoKid, test.JwtPubKeyNoKid}, false, false},
		{"testBothNoKidDifferent", args{test.JwtPubKeyNoKid, test.JwtPubKeyNoKid2}, true, false},
		{"testNewNoKeys", args{test.JwtPubKey1, test.JwtPubKeyNoKeys}, true, false},
		{"testOldNoKeys", args{test.JwtPubKeyNoKeys, test.JwtPubKey1}, true, false},
		{"testBothNoKeysSame", args{test.JwtPubKeyNoKeys, test.JwtPubKeyNoKeys}, false, false},
		{"testBothNoKeysDifferent", args{test.JwtPubKeyNoKeys, test.JwtPubKeyNoKeys2}, true, false},
		{"testNewExtraElements", args{test.JwtPubKey1, test.JwtPubKeyExtraElements}, true, false},
		{"testOldExtraElements", args{test.JwtPubKeyExtraElements, test.JwtPubKey1}, true, false},
		{"testBothExtraElements", args{test.JwtPubKeyExtraElements, test.JwtPubKeyExtraElements}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareJWKSResponse(tt.args.oldKeyString, tt.args.newKeyString)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareJWKSResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("compareJWKSResponse() got = %v, want %v", got, tt.want)
			}
		})
	}
}
