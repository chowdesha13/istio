/*
Copyright 2017 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutil

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	proto3 "github.com/golang/protobuf/ptypes/struct"
	pbt "github.com/golang/protobuf/ptypes/timestamp"
	pbs "google.golang.org/genproto/googleapis/rpc/status"
	sppb "google.golang.org/genproto/googleapis/spanner/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MockCloudSpannerClient is a mock implementation of sppb.SpannerClient.
type MockCloudSpannerClient struct {
	sppb.SpannerClient

	mu sync.Mutex
	t  *testing.T
	// Live sessions on the client.
	sessions map[string]bool
	// Session ping history.
	pings []string
	// Client will stall on any requests.
	freezed chan struct{}

	// Expected set of actions that have been executed by the client. These
	// interfaces should be type reflected against with *Request types in sppb,
	// such as sppb.GetSessionRequest. Buffered to a large degree.
	ReceivedRequests chan interface{}
}

// NewMockCloudSpannerClient creates new MockCloudSpannerClient instance.
func NewMockCloudSpannerClient(t *testing.T) *MockCloudSpannerClient {
	mc := &MockCloudSpannerClient{
		t:                t,
		sessions:         map[string]bool{},
		ReceivedRequests: make(chan interface{}, 100000),
	}

	// Produce a closed channel, so the default action of ready is to not block.
	mc.Freeze()
	mc.Unfreeze()

	return mc
}

// DumpPings dumps the ping history.
func (m *MockCloudSpannerClient) DumpPings() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.pings...)
}

// DumpSessions dumps the internal session table.
func (m *MockCloudSpannerClient) DumpSessions() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := map[string]bool{}
	for s, v := range m.sessions {
		st[s] = v
	}
	return st
}

// CreateSession is a placeholder for SpannerClient.CreateSession.
func (m *MockCloudSpannerClient) CreateSession(ctx context.Context, r *sppb.CreateSessionRequest, opts ...grpc.CallOption) (*sppb.Session, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	s := &sppb.Session{}
	if r.Database != "mockdb" {
		// Reject other databases
		return s, status.Errorf(codes.NotFound, fmt.Sprintf("database not found: %v", r.Database))
	}
	// Generate & record session name.
	s.Name = fmt.Sprintf("mockdb-%v", time.Now().UnixNano())
	m.sessions[s.Name] = true
	return s, nil
}

// GetSession is a placeholder for SpannerClient.GetSession.
func (m *MockCloudSpannerClient) GetSession(ctx context.Context, r *sppb.GetSessionRequest, opts ...grpc.CallOption) (*sppb.Session, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pings = append(m.pings, r.Name)
	if _, ok := m.sessions[r.Name]; !ok {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("Session not found: %v", r.Name))
	}
	return &sppb.Session{Name: r.Name}, nil
}

// DeleteSession is a placeholder for SpannerClient.DeleteSession.
func (m *MockCloudSpannerClient) DeleteSession(ctx context.Context, r *sppb.DeleteSessionRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[r.Name]; !ok {
		// Session not found.
		return &empty.Empty{}, status.Errorf(codes.NotFound, fmt.Sprintf("Session not found: %v", r.Name))
	}
	// Delete session from in-memory table.
	delete(m.sessions, r.Name)
	return &empty.Empty{}, nil
}

// ExecuteSql is a placeholder for SpannerClient.ExecuteSql.
func (m *MockCloudSpannerClient) ExecuteSql(ctx context.Context, r *sppb.ExecuteSqlRequest, opts ...grpc.CallOption) (*sppb.ResultSet, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	return &sppb.ResultSet{Stats: &sppb.ResultSetStats{RowCount: &sppb.ResultSetStats_RowCountExact{7}}}, nil
}

// ExecuteBatchDml is a placeholder for SpannerClient.ExecuteBatchDml.
func (m *MockCloudSpannerClient) ExecuteBatchDml(ctx context.Context, r *sppb.ExecuteBatchDmlRequest, opts ...grpc.CallOption) (*sppb.ExecuteBatchDmlResponse, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	return &sppb.ExecuteBatchDmlResponse{Status: &pbs.Status{Code: 0}, ResultSets: []*sppb.ResultSet{}}, nil
}

// ExecuteStreamingSql is a mock implementation of SpannerClient.ExecuteStreamingSql.
func (m *MockCloudSpannerClient) ExecuteStreamingSql(ctx context.Context, r *sppb.ExecuteSqlRequest, opts ...grpc.CallOption) (sppb.Spanner_ExecuteStreamingSqlClient, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	wantReq := &sppb.ExecuteSqlRequest{
		Session: "mocksession",
		Transaction: &sppb.TransactionSelector{
			Selector: &sppb.TransactionSelector_SingleUse{
				SingleUse: &sppb.TransactionOptions{
					Mode: &sppb.TransactionOptions_ReadOnly_{
						ReadOnly: &sppb.TransactionOptions_ReadOnly{
							TimestampBound: &sppb.TransactionOptions_ReadOnly_Strong{
								Strong: true,
							},
							ReturnReadTimestamp: false,
						},
					},
				},
			},
		},
		Sql: "mockquery",
		Params: &proto3.Struct{
			Fields: map[string]*proto3.Value{"var1": {Kind: &proto3.Value_StringValue{StringValue: "abc"}}},
		},
		ParamTypes: map[string]*sppb.Type{"var1": {Code: sppb.TypeCode_STRING}},
	}
	if !proto.Equal(r, wantReq) {
		return nil, fmt.Errorf("got query request: %v, want: %v", r, wantReq)
	}
	return nil, errors.New("query never succeeds on mock client")
}

// StreamingRead is a placeholder for SpannerClient.StreamingRead.
func (m *MockCloudSpannerClient) StreamingRead(ctx context.Context, r *sppb.ReadRequest, opts ...grpc.CallOption) (sppb.Spanner_StreamingReadClient, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	wantReq := &sppb.ReadRequest{
		Session: "mocksession",
		Transaction: &sppb.TransactionSelector{
			Selector: &sppb.TransactionSelector_SingleUse{
				SingleUse: &sppb.TransactionOptions{
					Mode: &sppb.TransactionOptions_ReadOnly_{
						ReadOnly: &sppb.TransactionOptions_ReadOnly{
							TimestampBound: &sppb.TransactionOptions_ReadOnly_Strong{
								Strong: true,
							},
							ReturnReadTimestamp: false,
						},
					},
				},
			},
		},
		Table:   "t_mock",
		Columns: []string{"col1", "col2"},
		KeySet: &sppb.KeySet{
			Keys: []*proto3.ListValue{
				{
					Values: []*proto3.Value{
						{Kind: &proto3.Value_StringValue{StringValue: "foo"}},
					},
				},
			},
			Ranges: []*sppb.KeyRange{},
			All:    false,
		},
	}
	if !proto.Equal(r, wantReq) {
		return nil, fmt.Errorf("got query request: %v, want: %v", r, wantReq)
	}
	return nil, errors.New("read never succeeds on mock client")
}

// BeginTransaction is a placeholder for SpannerClient.BeginTransaction.
func (m *MockCloudSpannerClient) BeginTransaction(ctx context.Context, r *sppb.BeginTransactionRequest, opts ...grpc.CallOption) (*sppb.Transaction, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	resp := &sppb.Transaction{Id: []byte("transaction-1")}
	if _, ok := r.Options.Mode.(*sppb.TransactionOptions_ReadOnly_); ok {
		resp.ReadTimestamp = &pbt.Timestamp{Seconds: 3, Nanos: 4}
	}
	return resp, nil
}

// Commit is a placeholder for SpannerClient.Commit.
func (m *MockCloudSpannerClient) Commit(ctx context.Context, r *sppb.CommitRequest, opts ...grpc.CallOption) (*sppb.CommitResponse, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	return &sppb.CommitResponse{CommitTimestamp: &pbt.Timestamp{Seconds: 1, Nanos: 2}}, nil
}

// Rollback is a placeholder for SpannerClient.Rollback.
func (m *MockCloudSpannerClient) Rollback(ctx context.Context, r *sppb.RollbackRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	m.ready()
	m.ReceivedRequests <- r

	m.mu.Lock()
	defer m.mu.Unlock()
	return nil, nil
}

// PartitionQuery is a placeholder for SpannerServer.PartitionQuery.
func (m *MockCloudSpannerClient) PartitionQuery(ctx context.Context, r *sppb.PartitionQueryRequest, opts ...grpc.CallOption) (*sppb.PartitionResponse, error) {
	m.ready()
	m.ReceivedRequests <- r

	return nil, errors.New("Unimplemented")
}

// PartitionRead is a placeholder for SpannerServer.PartitionRead.
func (m *MockCloudSpannerClient) PartitionRead(ctx context.Context, r *sppb.PartitionReadRequest, opts ...grpc.CallOption) (*sppb.PartitionResponse, error) {
	m.ready()
	m.ReceivedRequests <- r

	return nil, errors.New("Unimplemented")
}

// Freeze stalls all requests.
func (m *MockCloudSpannerClient) Freeze() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.freezed = make(chan struct{})
}

// Unfreeze restores processing requests.
func (m *MockCloudSpannerClient) Unfreeze() {
	m.mu.Lock()
	defer m.mu.Unlock()
	close(m.freezed)
}

// ready checks conditions before executing requests
// TODO: add checks for injected errors, actions
func (m *MockCloudSpannerClient) ready() {
	m.mu.Lock()
	freezed := m.freezed
	m.mu.Unlock()
	// check if client should be freezed
	<-freezed
}
