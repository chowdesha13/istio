// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/cloud/scheduler/v1beta1/cloudscheduler.proto

package scheduler // import "google.golang.org/genproto/googleapis/cloud/scheduler/v1beta1"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import empty "github.com/golang/protobuf/ptypes/empty"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import field_mask "google.golang.org/genproto/protobuf/field_mask"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Request message for listing jobs using [ListJobs][google.cloud.scheduler.v1beta1.CloudScheduler.ListJobs].
type ListJobsRequest struct {
	// Required.
	//
	// The location name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID`.
	Parent string `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	// Requested page size.
	//
	// The maximum page size is 500. If unspecified, the page size will
	// be the maximum. Fewer jobs than requested might be returned,
	// even if more jobs exist; use next_page_token to determine if more
	// jobs exist.
	PageSize int32 `protobuf:"varint,5,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// A token identifying a page of results the server will return. To
	// request the first page results, page_token must be empty. To
	// request the next page of results, page_token must be the value of
	// [next_page_token][google.cloud.scheduler.v1beta1.ListJobsResponse.next_page_token] returned from
	// the previous call to [ListJobs][google.cloud.scheduler.v1beta1.CloudScheduler.ListJobs]. It is an error to
	// switch the value of [filter][google.cloud.scheduler.v1beta1.ListJobsRequest.filter] or
	// [order_by][google.cloud.scheduler.v1beta1.ListJobsRequest.order_by] while iterating through pages.
	PageToken            string   `protobuf:"bytes,6,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListJobsRequest) Reset()         { *m = ListJobsRequest{} }
func (m *ListJobsRequest) String() string { return proto.CompactTextString(m) }
func (*ListJobsRequest) ProtoMessage()    {}
func (*ListJobsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{0}
}
func (m *ListJobsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListJobsRequest.Unmarshal(m, b)
}
func (m *ListJobsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListJobsRequest.Marshal(b, m, deterministic)
}
func (dst *ListJobsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListJobsRequest.Merge(dst, src)
}
func (m *ListJobsRequest) XXX_Size() int {
	return xxx_messageInfo_ListJobsRequest.Size(m)
}
func (m *ListJobsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListJobsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListJobsRequest proto.InternalMessageInfo

func (m *ListJobsRequest) GetParent() string {
	if m != nil {
		return m.Parent
	}
	return ""
}

func (m *ListJobsRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListJobsRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

// Response message for listing jobs using [ListJobs][google.cloud.scheduler.v1beta1.CloudScheduler.ListJobs].
type ListJobsResponse struct {
	// The list of jobs.
	Jobs []*Job `protobuf:"bytes,1,rep,name=jobs,proto3" json:"jobs,omitempty"`
	// A token to retrieve next page of results. Pass this value in the
	// [page_token][google.cloud.scheduler.v1beta1.ListJobsRequest.page_token] field in the subsequent call to
	// [ListJobs][google.cloud.scheduler.v1beta1.CloudScheduler.ListJobs] to retrieve the next page of results.
	// If this is empty it indicates that there are no more results
	// through which to paginate.
	//
	// The page token is valid for only 2 hours.
	NextPageToken        string   `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListJobsResponse) Reset()         { *m = ListJobsResponse{} }
func (m *ListJobsResponse) String() string { return proto.CompactTextString(m) }
func (*ListJobsResponse) ProtoMessage()    {}
func (*ListJobsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{1}
}
func (m *ListJobsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListJobsResponse.Unmarshal(m, b)
}
func (m *ListJobsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListJobsResponse.Marshal(b, m, deterministic)
}
func (dst *ListJobsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListJobsResponse.Merge(dst, src)
}
func (m *ListJobsResponse) XXX_Size() int {
	return xxx_messageInfo_ListJobsResponse.Size(m)
}
func (m *ListJobsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListJobsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListJobsResponse proto.InternalMessageInfo

func (m *ListJobsResponse) GetJobs() []*Job {
	if m != nil {
		return m.Jobs
	}
	return nil
}

func (m *ListJobsResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

// Request message for [GetJob][google.cloud.scheduler.v1beta1.CloudScheduler.GetJob].
type GetJobRequest struct {
	// Required.
	//
	// The job name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID/jobs/JOB_ID`.
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetJobRequest) Reset()         { *m = GetJobRequest{} }
func (m *GetJobRequest) String() string { return proto.CompactTextString(m) }
func (*GetJobRequest) ProtoMessage()    {}
func (*GetJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{2}
}
func (m *GetJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetJobRequest.Unmarshal(m, b)
}
func (m *GetJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetJobRequest.Marshal(b, m, deterministic)
}
func (dst *GetJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetJobRequest.Merge(dst, src)
}
func (m *GetJobRequest) XXX_Size() int {
	return xxx_messageInfo_GetJobRequest.Size(m)
}
func (m *GetJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetJobRequest proto.InternalMessageInfo

func (m *GetJobRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Request message for [CreateJob][google.cloud.scheduler.v1beta1.CloudScheduler.CreateJob].
type CreateJobRequest struct {
	// Required.
	//
	// The location name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID`.
	Parent string `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	// Required.
	//
	// The job to add. The user can optionally specify a name for the
	// job in [name][google.cloud.scheduler.v1beta1.Job.name]. [name][google.cloud.scheduler.v1beta1.Job.name] cannot be the same as an
	// existing job. If a name is not specified then the system will
	// generate a random unique name that will be returned
	// ([name][google.cloud.scheduler.v1beta1.Job.name]) in the response.
	Job                  *Job     `protobuf:"bytes,2,opt,name=job,proto3" json:"job,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateJobRequest) Reset()         { *m = CreateJobRequest{} }
func (m *CreateJobRequest) String() string { return proto.CompactTextString(m) }
func (*CreateJobRequest) ProtoMessage()    {}
func (*CreateJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{3}
}
func (m *CreateJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateJobRequest.Unmarshal(m, b)
}
func (m *CreateJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateJobRequest.Marshal(b, m, deterministic)
}
func (dst *CreateJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateJobRequest.Merge(dst, src)
}
func (m *CreateJobRequest) XXX_Size() int {
	return xxx_messageInfo_CreateJobRequest.Size(m)
}
func (m *CreateJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateJobRequest proto.InternalMessageInfo

func (m *CreateJobRequest) GetParent() string {
	if m != nil {
		return m.Parent
	}
	return ""
}

func (m *CreateJobRequest) GetJob() *Job {
	if m != nil {
		return m.Job
	}
	return nil
}

// Request message for [UpdateJob][google.cloud.scheduler.v1beta1.CloudScheduler.UpdateJob].
type UpdateJobRequest struct {
	// Required.
	//
	// The new job properties. [name][google.cloud.scheduler.v1beta1.Job.name] must be specified.
	//
	// Output only fields cannot be modified using UpdateJob.
	// Any value specified for an output only field will be ignored.
	Job *Job `protobuf:"bytes,1,opt,name=job,proto3" json:"job,omitempty"`
	// A  mask used to specify which fields of the job are being updated.
	UpdateMask           *field_mask.FieldMask `protobuf:"bytes,2,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *UpdateJobRequest) Reset()         { *m = UpdateJobRequest{} }
func (m *UpdateJobRequest) String() string { return proto.CompactTextString(m) }
func (*UpdateJobRequest) ProtoMessage()    {}
func (*UpdateJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{4}
}
func (m *UpdateJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UpdateJobRequest.Unmarshal(m, b)
}
func (m *UpdateJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UpdateJobRequest.Marshal(b, m, deterministic)
}
func (dst *UpdateJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UpdateJobRequest.Merge(dst, src)
}
func (m *UpdateJobRequest) XXX_Size() int {
	return xxx_messageInfo_UpdateJobRequest.Size(m)
}
func (m *UpdateJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_UpdateJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_UpdateJobRequest proto.InternalMessageInfo

func (m *UpdateJobRequest) GetJob() *Job {
	if m != nil {
		return m.Job
	}
	return nil
}

func (m *UpdateJobRequest) GetUpdateMask() *field_mask.FieldMask {
	if m != nil {
		return m.UpdateMask
	}
	return nil
}

// Request message for deleting a job using
// [DeleteJob][google.cloud.scheduler.v1beta1.CloudScheduler.DeleteJob].
type DeleteJobRequest struct {
	// Required.
	//
	// The job name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID/jobs/JOB_ID`.
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteJobRequest) Reset()         { *m = DeleteJobRequest{} }
func (m *DeleteJobRequest) String() string { return proto.CompactTextString(m) }
func (*DeleteJobRequest) ProtoMessage()    {}
func (*DeleteJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{5}
}
func (m *DeleteJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteJobRequest.Unmarshal(m, b)
}
func (m *DeleteJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteJobRequest.Marshal(b, m, deterministic)
}
func (dst *DeleteJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteJobRequest.Merge(dst, src)
}
func (m *DeleteJobRequest) XXX_Size() int {
	return xxx_messageInfo_DeleteJobRequest.Size(m)
}
func (m *DeleteJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteJobRequest proto.InternalMessageInfo

func (m *DeleteJobRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Request message for [PauseJob][google.cloud.scheduler.v1beta1.CloudScheduler.PauseJob].
type PauseJobRequest struct {
	// Required.
	//
	// The job name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID/jobs/JOB_ID`.
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PauseJobRequest) Reset()         { *m = PauseJobRequest{} }
func (m *PauseJobRequest) String() string { return proto.CompactTextString(m) }
func (*PauseJobRequest) ProtoMessage()    {}
func (*PauseJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{6}
}
func (m *PauseJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PauseJobRequest.Unmarshal(m, b)
}
func (m *PauseJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PauseJobRequest.Marshal(b, m, deterministic)
}
func (dst *PauseJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PauseJobRequest.Merge(dst, src)
}
func (m *PauseJobRequest) XXX_Size() int {
	return xxx_messageInfo_PauseJobRequest.Size(m)
}
func (m *PauseJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PauseJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PauseJobRequest proto.InternalMessageInfo

func (m *PauseJobRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Request message for [ResumeJob][google.cloud.scheduler.v1beta1.CloudScheduler.ResumeJob].
type ResumeJobRequest struct {
	// Required.
	//
	// The job name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID/jobs/JOB_ID`.
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ResumeJobRequest) Reset()         { *m = ResumeJobRequest{} }
func (m *ResumeJobRequest) String() string { return proto.CompactTextString(m) }
func (*ResumeJobRequest) ProtoMessage()    {}
func (*ResumeJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{7}
}
func (m *ResumeJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResumeJobRequest.Unmarshal(m, b)
}
func (m *ResumeJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResumeJobRequest.Marshal(b, m, deterministic)
}
func (dst *ResumeJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResumeJobRequest.Merge(dst, src)
}
func (m *ResumeJobRequest) XXX_Size() int {
	return xxx_messageInfo_ResumeJobRequest.Size(m)
}
func (m *ResumeJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ResumeJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ResumeJobRequest proto.InternalMessageInfo

func (m *ResumeJobRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Request message for forcing a job to run now using
// [RunJob][google.cloud.scheduler.v1beta1.CloudScheduler.RunJob].
type RunJobRequest struct {
	// Required.
	//
	// The job name. For example:
	// `projects/PROJECT_ID/locations/LOCATION_ID/jobs/JOB_ID`.
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RunJobRequest) Reset()         { *m = RunJobRequest{} }
func (m *RunJobRequest) String() string { return proto.CompactTextString(m) }
func (*RunJobRequest) ProtoMessage()    {}
func (*RunJobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cloudscheduler_83896ba95dd284d1, []int{8}
}
func (m *RunJobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RunJobRequest.Unmarshal(m, b)
}
func (m *RunJobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RunJobRequest.Marshal(b, m, deterministic)
}
func (dst *RunJobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RunJobRequest.Merge(dst, src)
}
func (m *RunJobRequest) XXX_Size() int {
	return xxx_messageInfo_RunJobRequest.Size(m)
}
func (m *RunJobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_RunJobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_RunJobRequest proto.InternalMessageInfo

func (m *RunJobRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func init() {
	proto.RegisterType((*ListJobsRequest)(nil), "google.cloud.scheduler.v1beta1.ListJobsRequest")
	proto.RegisterType((*ListJobsResponse)(nil), "google.cloud.scheduler.v1beta1.ListJobsResponse")
	proto.RegisterType((*GetJobRequest)(nil), "google.cloud.scheduler.v1beta1.GetJobRequest")
	proto.RegisterType((*CreateJobRequest)(nil), "google.cloud.scheduler.v1beta1.CreateJobRequest")
	proto.RegisterType((*UpdateJobRequest)(nil), "google.cloud.scheduler.v1beta1.UpdateJobRequest")
	proto.RegisterType((*DeleteJobRequest)(nil), "google.cloud.scheduler.v1beta1.DeleteJobRequest")
	proto.RegisterType((*PauseJobRequest)(nil), "google.cloud.scheduler.v1beta1.PauseJobRequest")
	proto.RegisterType((*ResumeJobRequest)(nil), "google.cloud.scheduler.v1beta1.ResumeJobRequest")
	proto.RegisterType((*RunJobRequest)(nil), "google.cloud.scheduler.v1beta1.RunJobRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// CloudSchedulerClient is the client API for CloudScheduler service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CloudSchedulerClient interface {
	// Lists jobs.
	ListJobs(ctx context.Context, in *ListJobsRequest, opts ...grpc.CallOption) (*ListJobsResponse, error)
	// Gets a job.
	GetJob(ctx context.Context, in *GetJobRequest, opts ...grpc.CallOption) (*Job, error)
	// Creates a job.
	CreateJob(ctx context.Context, in *CreateJobRequest, opts ...grpc.CallOption) (*Job, error)
	// Updates a job.
	//
	// If successful, the updated [Job][google.cloud.scheduler.v1beta1.Job] is returned. If the job does
	// not exist, `NOT_FOUND` is returned.
	//
	// If UpdateJob does not successfully return, it is possible for the
	// job to be in an [Job.State.UPDATE_FAILED][google.cloud.scheduler.v1beta1.Job.State.UPDATE_FAILED] state. A job in this state may
	// not be executed. If this happens, retry the UpdateJob request
	// until a successful response is received.
	UpdateJob(ctx context.Context, in *UpdateJobRequest, opts ...grpc.CallOption) (*Job, error)
	// Deletes a job.
	DeleteJob(ctx context.Context, in *DeleteJobRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// Pauses a job.
	//
	// If a job is paused then the system will stop executing the job
	// until it is re-enabled via [ResumeJob][google.cloud.scheduler.v1beta1.CloudScheduler.ResumeJob]. The
	// state of the job is stored in [state][google.cloud.scheduler.v1beta1.Job.state]; if paused it
	// will be set to [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED]. A job must be in [Job.State.ENABLED][google.cloud.scheduler.v1beta1.Job.State.ENABLED]
	// to be paused.
	PauseJob(ctx context.Context, in *PauseJobRequest, opts ...grpc.CallOption) (*Job, error)
	// Resume a job.
	//
	// This method reenables a job after it has been [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED]. The
	// state of a job is stored in [Job.state][google.cloud.scheduler.v1beta1.Job.state]; after calling this method it
	// will be set to [Job.State.ENABLED][google.cloud.scheduler.v1beta1.Job.State.ENABLED]. A job must be in
	// [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED] to be resumed.
	ResumeJob(ctx context.Context, in *ResumeJobRequest, opts ...grpc.CallOption) (*Job, error)
	// Forces a job to run now.
	//
	// When this method is called, Cloud Scheduler will dispatch the job, even
	// if the job is already running.
	RunJob(ctx context.Context, in *RunJobRequest, opts ...grpc.CallOption) (*Job, error)
}

type cloudSchedulerClient struct {
	cc *grpc.ClientConn
}

func NewCloudSchedulerClient(cc *grpc.ClientConn) CloudSchedulerClient {
	return &cloudSchedulerClient{cc}
}

func (c *cloudSchedulerClient) ListJobs(ctx context.Context, in *ListJobsRequest, opts ...grpc.CallOption) (*ListJobsResponse, error) {
	out := new(ListJobsResponse)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/ListJobs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) GetJob(ctx context.Context, in *GetJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/GetJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) CreateJob(ctx context.Context, in *CreateJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/CreateJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) UpdateJob(ctx context.Context, in *UpdateJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/UpdateJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) DeleteJob(ctx context.Context, in *DeleteJobRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/DeleteJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) PauseJob(ctx context.Context, in *PauseJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/PauseJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) ResumeJob(ctx context.Context, in *ResumeJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/ResumeJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudSchedulerClient) RunJob(ctx context.Context, in *RunJobRequest, opts ...grpc.CallOption) (*Job, error) {
	out := new(Job)
	err := c.cc.Invoke(ctx, "/google.cloud.scheduler.v1beta1.CloudScheduler/RunJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CloudSchedulerServer is the server API for CloudScheduler service.
type CloudSchedulerServer interface {
	// Lists jobs.
	ListJobs(context.Context, *ListJobsRequest) (*ListJobsResponse, error)
	// Gets a job.
	GetJob(context.Context, *GetJobRequest) (*Job, error)
	// Creates a job.
	CreateJob(context.Context, *CreateJobRequest) (*Job, error)
	// Updates a job.
	//
	// If successful, the updated [Job][google.cloud.scheduler.v1beta1.Job] is returned. If the job does
	// not exist, `NOT_FOUND` is returned.
	//
	// If UpdateJob does not successfully return, it is possible for the
	// job to be in an [Job.State.UPDATE_FAILED][google.cloud.scheduler.v1beta1.Job.State.UPDATE_FAILED] state. A job in this state may
	// not be executed. If this happens, retry the UpdateJob request
	// until a successful response is received.
	UpdateJob(context.Context, *UpdateJobRequest) (*Job, error)
	// Deletes a job.
	DeleteJob(context.Context, *DeleteJobRequest) (*empty.Empty, error)
	// Pauses a job.
	//
	// If a job is paused then the system will stop executing the job
	// until it is re-enabled via [ResumeJob][google.cloud.scheduler.v1beta1.CloudScheduler.ResumeJob]. The
	// state of the job is stored in [state][google.cloud.scheduler.v1beta1.Job.state]; if paused it
	// will be set to [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED]. A job must be in [Job.State.ENABLED][google.cloud.scheduler.v1beta1.Job.State.ENABLED]
	// to be paused.
	PauseJob(context.Context, *PauseJobRequest) (*Job, error)
	// Resume a job.
	//
	// This method reenables a job after it has been [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED]. The
	// state of a job is stored in [Job.state][google.cloud.scheduler.v1beta1.Job.state]; after calling this method it
	// will be set to [Job.State.ENABLED][google.cloud.scheduler.v1beta1.Job.State.ENABLED]. A job must be in
	// [Job.State.PAUSED][google.cloud.scheduler.v1beta1.Job.State.PAUSED] to be resumed.
	ResumeJob(context.Context, *ResumeJobRequest) (*Job, error)
	// Forces a job to run now.
	//
	// When this method is called, Cloud Scheduler will dispatch the job, even
	// if the job is already running.
	RunJob(context.Context, *RunJobRequest) (*Job, error)
}

func RegisterCloudSchedulerServer(s *grpc.Server, srv CloudSchedulerServer) {
	s.RegisterService(&_CloudScheduler_serviceDesc, srv)
}

func _CloudScheduler_ListJobs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListJobsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).ListJobs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/ListJobs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).ListJobs(ctx, req.(*ListJobsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_GetJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).GetJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/GetJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).GetJob(ctx, req.(*GetJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_CreateJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).CreateJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/CreateJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).CreateJob(ctx, req.(*CreateJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_UpdateJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).UpdateJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/UpdateJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).UpdateJob(ctx, req.(*UpdateJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_DeleteJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).DeleteJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/DeleteJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).DeleteJob(ctx, req.(*DeleteJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_PauseJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PauseJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).PauseJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/PauseJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).PauseJob(ctx, req.(*PauseJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_ResumeJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResumeJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).ResumeJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/ResumeJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).ResumeJob(ctx, req.(*ResumeJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudScheduler_RunJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RunJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudSchedulerServer).RunJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.cloud.scheduler.v1beta1.CloudScheduler/RunJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudSchedulerServer).RunJob(ctx, req.(*RunJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CloudScheduler_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.cloud.scheduler.v1beta1.CloudScheduler",
	HandlerType: (*CloudSchedulerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListJobs",
			Handler:    _CloudScheduler_ListJobs_Handler,
		},
		{
			MethodName: "GetJob",
			Handler:    _CloudScheduler_GetJob_Handler,
		},
		{
			MethodName: "CreateJob",
			Handler:    _CloudScheduler_CreateJob_Handler,
		},
		{
			MethodName: "UpdateJob",
			Handler:    _CloudScheduler_UpdateJob_Handler,
		},
		{
			MethodName: "DeleteJob",
			Handler:    _CloudScheduler_DeleteJob_Handler,
		},
		{
			MethodName: "PauseJob",
			Handler:    _CloudScheduler_PauseJob_Handler,
		},
		{
			MethodName: "ResumeJob",
			Handler:    _CloudScheduler_ResumeJob_Handler,
		},
		{
			MethodName: "RunJob",
			Handler:    _CloudScheduler_RunJob_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/cloud/scheduler/v1beta1/cloudscheduler.proto",
}

func init() {
	proto.RegisterFile("google/cloud/scheduler/v1beta1/cloudscheduler.proto", fileDescriptor_cloudscheduler_83896ba95dd284d1)
}

var fileDescriptor_cloudscheduler_83896ba95dd284d1 = []byte{
	// 731 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x96, 0x4b, 0x4f, 0xdb, 0x4a,
	0x14, 0xc7, 0x35, 0x3c, 0x22, 0x72, 0x10, 0x10, 0xcd, 0x02, 0xe5, 0x86, 0x7b, 0xaf, 0x22, 0xa3,
	0x8b, 0xa2, 0x48, 0x64, 0x6e, 0x78, 0xf4, 0x11, 0xfa, 0x90, 0x78, 0x94, 0x0a, 0x51, 0x29, 0x32,
	0x65, 0xd3, 0x0d, 0x1a, 0x27, 0x83, 0xeb, 0xe0, 0x78, 0x5c, 0x8f, 0x5d, 0xb5, 0x54, 0x6c, 0xba,
	0xa8, 0x2a, 0xb5, 0x3b, 0x76, 0x5d, 0x54, 0x15, 0xed, 0x37, 0xea, 0x57, 0xe8, 0x07, 0xa9, 0x66,
	0xfc, 0x80, 0xb8, 0x80, 0xed, 0x5d, 0x3c, 0xe7, 0x9c, 0x39, 0xbf, 0x39, 0xe7, 0xfc, 0x8f, 0x02,
	0xab, 0x26, 0xe7, 0xa6, 0xcd, 0x48, 0xcf, 0xe6, 0x41, 0x9f, 0x88, 0xde, 0x4b, 0xd6, 0x0f, 0x6c,
	0xe6, 0x91, 0xd7, 0x6d, 0x83, 0xf9, 0xb4, 0x1d, 0x9e, 0x27, 0xc7, 0x2d, 0xd7, 0xe3, 0x3e, 0xc7,
	0xff, 0x86, 0x41, 0x2d, 0x65, 0x6c, 0x5d, 0x5a, 0xa3, 0xa0, 0xda, 0xdf, 0xd1, 0xa5, 0xd4, 0xb5,
	0x08, 0x75, 0x1c, 0xee, 0x53, 0xdf, 0xe2, 0x8e, 0x08, 0xa3, 0x6b, 0x7f, 0x5d, 0xb1, 0x7a, 0x4c,
	0xf0, 0xc0, 0xeb, 0xb1, 0xc8, 0xd4, 0xc8, 0xa0, 0x19, 0x70, 0x23, 0xf2, 0x5c, 0x88, 0x3c, 0xd5,
	0x97, 0x11, 0x1c, 0x13, 0x36, 0x74, 0xfd, 0xb7, 0x91, 0xb1, 0x9e, 0x36, 0x1e, 0x5b, 0xcc, 0xee,
	0x1f, 0x0d, 0xa9, 0x38, 0x09, 0x3d, 0x34, 0x06, 0x73, 0xfb, 0x96, 0xf0, 0xf7, 0xb8, 0x21, 0x74,
	0xf6, 0x2a, 0x60, 0xc2, 0xc7, 0xf3, 0x50, 0x72, 0xa9, 0xc7, 0x1c, 0xbf, 0x8a, 0xea, 0xa8, 0x51,
	0xd6, 0xa3, 0x2f, 0xbc, 0x00, 0x65, 0x97, 0x9a, 0xec, 0x48, 0x58, 0xa7, 0xac, 0x3a, 0x59, 0x47,
	0x8d, 0x49, 0x7d, 0x4a, 0x1e, 0x1c, 0x58, 0xa7, 0x0c, 0xff, 0x03, 0xa0, 0x8c, 0x3e, 0x3f, 0x61,
	0x4e, 0xb5, 0xa4, 0x02, 0x95, 0xfb, 0x73, 0x79, 0xa0, 0x09, 0xa8, 0x5c, 0xa6, 0x11, 0x2e, 0x77,
	0x04, 0xc3, 0x77, 0x61, 0x62, 0xc0, 0x0d, 0x51, 0x45, 0xf5, 0xf1, 0xc6, 0xf4, 0xca, 0x62, 0xeb,
	0xf6, 0x5a, 0xb6, 0xf6, 0xb8, 0xa1, 0xab, 0x00, 0xbc, 0x04, 0x73, 0x0e, 0x7b, 0xe3, 0x1f, 0x5d,
	0x49, 0x38, 0xa6, 0x12, 0xce, 0xc8, 0xe3, 0x6e, 0x92, 0x74, 0x11, 0x66, 0x76, 0x99, 0xcc, 0x19,
	0xbf, 0x0c, 0xc3, 0x84, 0x43, 0x87, 0x2c, 0x7a, 0x97, 0xfa, 0xad, 0x51, 0xa8, 0x6c, 0x79, 0x8c,
	0xfa, 0xec, 0x8a, 0xdf, 0x4d, 0x15, 0x58, 0x87, 0xf1, 0x01, 0x37, 0x54, 0xb2, 0x9c, 0xc0, 0xd2,
	0x5f, 0xfb, 0x80, 0xa0, 0x72, 0xe8, 0xf6, 0x47, 0x73, 0x44, 0x77, 0xa1, 0x62, 0x77, 0xe1, 0x0d,
	0x98, 0x0e, 0xd4, 0x55, 0xaa, 0x89, 0x11, 0x4a, 0x2d, 0x0e, 0x8f, 0xfb, 0xdc, 0x7a, 0x22, 0xfb,
	0xfc, 0x8c, 0x8a, 0x13, 0x1d, 0x42, 0x77, 0xf9, 0x5b, 0x5b, 0x82, 0xca, 0x36, 0xb3, 0xd9, 0x08,
	0xc7, 0x75, 0x35, 0xf9, 0x0f, 0xe6, 0xba, 0x34, 0x10, 0x59, 0x6e, 0x4b, 0x50, 0xd1, 0x99, 0x08,
	0x86, 0x59, 0x7e, 0x8b, 0x30, 0xa3, 0x07, 0xce, 0xed, 0x4e, 0x2b, 0x1f, 0x01, 0x66, 0xb7, 0xe4,
	0xeb, 0x0f, 0xe2, 0xc7, 0xe3, 0x1f, 0x08, 0xa6, 0xe2, 0xa9, 0xc1, 0x24, 0xab, 0x44, 0xa9, 0x31,
	0xae, 0xfd, 0x9f, 0x3f, 0x20, 0x1c, 0x48, 0x6d, 0xfd, 0xfd, 0xcf, 0x5f, 0xe7, 0x63, 0x04, 0x2f,
	0x27, 0x32, 0x7b, 0x17, 0x36, 0xfe, 0xa1, 0xeb, 0xf1, 0x01, 0xeb, 0xf9, 0x82, 0x34, 0x89, 0xcd,
	0x7b, 0xa1, 0x88, 0x49, 0xf3, 0x8c, 0xa8, 0x71, 0x3c, 0x47, 0x50, 0x0a, 0xe7, 0x0c, 0x2f, 0x67,
	0xe5, 0x1c, 0x99, 0xc7, 0x5a, 0x9e, 0xb6, 0x5f, 0x47, 0x25, 0x0b, 0x76, 0x03, 0x93, 0x42, 0x22,
	0xcd, 0x33, 0xfc, 0x15, 0x41, 0x39, 0x19, 0x6c, 0x9c, 0x59, 0x8c, 0xb4, 0x06, 0xf2, 0xb1, 0x75,
	0x14, 0xdb, 0x9a, 0x56, 0xac, 0x62, 0x1d, 0x35, 0xc9, 0x17, 0x08, 0xca, 0x89, 0x2a, 0xb2, 0x01,
	0xd3, 0x02, 0xca, 0x07, 0xf8, 0x48, 0x01, 0xde, 0x5b, 0x69, 0x5f, 0x02, 0xca, 0xd5, 0x99, 0xa3,
	0x80, 0x21, 0xe4, 0x67, 0x04, 0xe5, 0x44, 0x32, 0xd9, 0x90, 0x69, 0x75, 0xd5, 0xe6, 0xff, 0x50,
	0xe6, 0x8e, 0x5c, 0xcf, 0x71, 0x53, 0x9b, 0x05, 0x9b, 0xfa, 0x0d, 0xc1, 0x54, 0xac, 0xcc, 0x6c,
	0x45, 0xa4, 0x34, 0x5c, 0xa8, 0x62, 0xda, 0x6a, 0x21, 0xb2, 0x8e, 0x2b, 0x73, 0x75, 0x50, 0x13,
	0x7f, 0x47, 0x50, 0x4e, 0xb6, 0x42, 0x76, 0xc5, 0xd2, 0x0b, 0x24, 0x1f, 0xe4, 0x63, 0x05, 0x79,
	0x5f, 0x5b, 0x2b, 0x06, 0xe9, 0xa9, 0x64, 0x92, 0xf2, 0x0b, 0x82, 0x52, 0xb8, 0x93, 0xb2, 0x35,
	0x3b, 0xb2, 0xbb, 0xf2, 0xf1, 0x3d, 0x50, 0x7c, 0x77, 0xb4, 0x76, 0x41, 0xbe, 0xc0, 0xe9, 0xa0,
	0xe6, 0xe6, 0x27, 0x04, 0x5a, 0x8f, 0x0f, 0x33, 0x12, 0x6d, 0xce, 0x26, 0x9b, 0xb2, 0x2b, 0x87,
	0xab, 0x8b, 0x5e, 0xec, 0x46, 0x11, 0x26, 0xb7, 0xa9, 0x63, 0xb6, 0xb8, 0x67, 0x12, 0x93, 0x39,
	0x6a, 0xf4, 0x48, 0x68, 0xa2, 0xae, 0x25, 0x6e, 0xfa, 0x53, 0xb1, 0x91, 0x9c, 0x5c, 0x8c, 0x95,
	0x0f, 0xb6, 0x9e, 0xee, 0x6c, 0x1f, 0xee, 0xef, 0xe8, 0x46, 0x49, 0xc5, 0xaf, 0xfe, 0x0e, 0x00,
	0x00, 0xff, 0xff, 0x42, 0xed, 0xf2, 0xae, 0x21, 0x09, 0x00, 0x00,
}
