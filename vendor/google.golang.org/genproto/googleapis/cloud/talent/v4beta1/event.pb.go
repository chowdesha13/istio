// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/cloud/talent/v4beta1/event.proto

package talent // import "google.golang.org/genproto/googleapis/cloud/talent/v4beta1"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// An enumeration of an event attributed to the behavior of the end user,
// such as a job seeker.
type JobEvent_JobEventType int32

const (
	// The event is unspecified by other provided values.
	JobEvent_JOB_EVENT_TYPE_UNSPECIFIED JobEvent_JobEventType = 0
	// The job seeker or other entity interacting with the service has
	// had a job rendered in their view, such as in a list of search results in
	// a compressed or clipped format. This event is typically associated with
	// the viewing of a jobs list on a single page by a job seeker.
	JobEvent_IMPRESSION JobEvent_JobEventType = 1
	// The job seeker, or other entity interacting with the service, has
	// viewed the details of a job, including the full description. This
	// event doesn't apply to the viewing a snippet of a job appearing as a
	// part of the job search results. Viewing a snippet is associated with an
	// [impression][google.cloud.talent.v4beta1.JobEvent.JobEventType.IMPRESSION]).
	JobEvent_VIEW JobEvent_JobEventType = 2
	// The job seeker or other entity interacting with the service
	// performed an action to view a job and was redirected to a different
	// website for job.
	JobEvent_VIEW_REDIRECT JobEvent_JobEventType = 3
	// The job seeker or other entity interacting with the service
	// began the process or demonstrated the intention of applying for a job.
	JobEvent_APPLICATION_START JobEvent_JobEventType = 4
	// The job seeker or other entity interacting with the service
	// submitted an application for a job.
	JobEvent_APPLICATION_FINISH JobEvent_JobEventType = 5
	// The job seeker or other entity interacting with the service
	// submitted an application for a job with a single click without
	// entering information. If a job seeker performs this action, send only
	// this event to the service. Do not also send
	// [JobEventType.APPLICATION_START][google.cloud.talent.v4beta1.JobEvent.JobEventType.APPLICATION_START] or [JobEventType.APPLICATION_FINISH][google.cloud.talent.v4beta1.JobEvent.JobEventType.APPLICATION_FINISH]
	// events.
	JobEvent_APPLICATION_QUICK_SUBMISSION JobEvent_JobEventType = 6
	// The job seeker or other entity interacting with the service
	// performed an action to apply to a job and was redirected to a different
	// website to complete the application.
	JobEvent_APPLICATION_REDIRECT JobEvent_JobEventType = 7
	// The job seeker or other entity interacting with the service began the
	// process or demonstrated the intention of applying for a job from the
	// search results page without viewing the details of the job posting.
	// If sending this event, JobEventType.VIEW event shouldn't be sent.
	JobEvent_APPLICATION_START_FROM_SEARCH JobEvent_JobEventType = 8
	// The job seeker, or other entity interacting with the service, performs an
	// action with a single click from the search results page to apply to a job
	// (without viewing the details of the job posting), and is redirected
	// to a different website to complete the application. If a candidate
	// performs this action, send only this event to the service. Do not also
	// send [JobEventType.APPLICATION_START][google.cloud.talent.v4beta1.JobEvent.JobEventType.APPLICATION_START],
	// [JobEventType.APPLICATION_FINISH][google.cloud.talent.v4beta1.JobEvent.JobEventType.APPLICATION_FINISH] or [JobEventType.VIEW][google.cloud.talent.v4beta1.JobEvent.JobEventType.VIEW] events.
	JobEvent_APPLICATION_REDIRECT_FROM_SEARCH JobEvent_JobEventType = 9
	// This event should be used when a company submits an application
	// on behalf of a job seeker. This event is intended for use by staffing
	// agencies attempting to place candidates.
	JobEvent_APPLICATION_COMPANY_SUBMIT JobEvent_JobEventType = 10
	// The job seeker or other entity interacting with the service demonstrated
	// an interest in a job by bookmarking or saving it.
	JobEvent_BOOKMARK JobEvent_JobEventType = 11
	// The job seeker or other entity interacting with the service was
	// sent a notification, such as an email alert or device notification,
	// containing one or more jobs listings generated by the service.
	JobEvent_NOTIFICATION JobEvent_JobEventType = 12
	// The job seeker or other entity interacting with the service was
	// employed by the hiring entity (employer). Send this event
	// only if the job seeker was hired through an application that was
	// initiated by a search conducted through the Cloud Talent Solution
	// service.
	JobEvent_HIRED JobEvent_JobEventType = 13
	// A recruiter or staffing agency submitted an application on behalf of the
	// candidate after interacting with the service to identify a suitable job
	// posting.
	JobEvent_SENT_CV JobEvent_JobEventType = 14
	// The entity interacting with the service (for example, the job seeker),
	// was granted an initial interview by the hiring entity (employer). This
	// event should only be sent if the job seeker was granted an interview as
	// part of an application that was initiated by a search conducted through /
	// recommendation provided by the Cloud Talent Solution service.
	JobEvent_INTERVIEW_GRANTED JobEvent_JobEventType = 15
	// The job seeker or other entity interacting with the service showed
	// no interest in the job.
	JobEvent_NOT_INTERESTED JobEvent_JobEventType = 16
)

var JobEvent_JobEventType_name = map[int32]string{
	0:  "JOB_EVENT_TYPE_UNSPECIFIED",
	1:  "IMPRESSION",
	2:  "VIEW",
	3:  "VIEW_REDIRECT",
	4:  "APPLICATION_START",
	5:  "APPLICATION_FINISH",
	6:  "APPLICATION_QUICK_SUBMISSION",
	7:  "APPLICATION_REDIRECT",
	8:  "APPLICATION_START_FROM_SEARCH",
	9:  "APPLICATION_REDIRECT_FROM_SEARCH",
	10: "APPLICATION_COMPANY_SUBMIT",
	11: "BOOKMARK",
	12: "NOTIFICATION",
	13: "HIRED",
	14: "SENT_CV",
	15: "INTERVIEW_GRANTED",
	16: "NOT_INTERESTED",
}
var JobEvent_JobEventType_value = map[string]int32{
	"JOB_EVENT_TYPE_UNSPECIFIED":       0,
	"IMPRESSION":                       1,
	"VIEW":                             2,
	"VIEW_REDIRECT":                    3,
	"APPLICATION_START":                4,
	"APPLICATION_FINISH":               5,
	"APPLICATION_QUICK_SUBMISSION":     6,
	"APPLICATION_REDIRECT":             7,
	"APPLICATION_START_FROM_SEARCH":    8,
	"APPLICATION_REDIRECT_FROM_SEARCH": 9,
	"APPLICATION_COMPANY_SUBMIT":       10,
	"BOOKMARK":                         11,
	"NOTIFICATION":                     12,
	"HIRED":                            13,
	"SENT_CV":                          14,
	"INTERVIEW_GRANTED":                15,
	"NOT_INTERESTED":                   16,
}

func (x JobEvent_JobEventType) String() string {
	return proto.EnumName(JobEvent_JobEventType_name, int32(x))
}
func (JobEvent_JobEventType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_event_63120bd8ed2e89e0, []int{1, 0}
}

// The enum represents types of client events for a candidate profile.
type ProfileEvent_ProfileEventType int32

const (
	// Default value.
	ProfileEvent_PROFILE_EVENT_TYPE_UNSPECIFIED ProfileEvent_ProfileEventType = 0
	// The profile is displayed.
	ProfileEvent_IMPRESSION ProfileEvent_ProfileEventType = 1
	// The profile is viewed.
	ProfileEvent_VIEW ProfileEvent_ProfileEventType = 2
	// The profile is bookmarked.
	ProfileEvent_BOOKMARK ProfileEvent_ProfileEventType = 3
)

var ProfileEvent_ProfileEventType_name = map[int32]string{
	0: "PROFILE_EVENT_TYPE_UNSPECIFIED",
	1: "IMPRESSION",
	2: "VIEW",
	3: "BOOKMARK",
}
var ProfileEvent_ProfileEventType_value = map[string]int32{
	"PROFILE_EVENT_TYPE_UNSPECIFIED": 0,
	"IMPRESSION":                     1,
	"VIEW":                           2,
	"BOOKMARK":                       3,
}

func (x ProfileEvent_ProfileEventType) String() string {
	return proto.EnumName(ProfileEvent_ProfileEventType_name, int32(x))
}
func (ProfileEvent_ProfileEventType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_event_63120bd8ed2e89e0, []int{2, 0}
}

// An event issued when an end user interacts with the application that
// implements Cloud Talent Solution. Providing this information improves the
// quality of search and recommendation for the API clients, enabling the
// service to perform optimally. The number of events sent must be consistent
// with other calls, such as job searches, issued to the service by the client.
type ClientEvent struct {
	// Required.
	//
	// A unique ID generated in the API responses. It can be found in
	// [ResponseMetadata.request_id][google.cloud.talent.v4beta1.ResponseMetadata.request_id].
	RequestId string `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// Required.
	//
	// A unique identifier, generated by the client application.
	EventId string `protobuf:"bytes,2,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
	// Required.
	//
	// The timestamp of the event.
	CreateTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// Required.
	//
	// The detail information of a specific event type.
	//
	// Types that are valid to be assigned to Event:
	//	*ClientEvent_JobEvent
	//	*ClientEvent_ProfileEvent
	Event isClientEvent_Event `protobuf_oneof:"event"`
	// Optional.
	//
	// Notes about the event provided by recruiters or other users, for example,
	// feedback on why a profile was bookmarked.
	EventNotes           string   `protobuf:"bytes,9,opt,name=event_notes,json=eventNotes,proto3" json:"event_notes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientEvent) Reset()         { *m = ClientEvent{} }
func (m *ClientEvent) String() string { return proto.CompactTextString(m) }
func (*ClientEvent) ProtoMessage()    {}
func (*ClientEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_event_63120bd8ed2e89e0, []int{0}
}
func (m *ClientEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientEvent.Unmarshal(m, b)
}
func (m *ClientEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientEvent.Marshal(b, m, deterministic)
}
func (dst *ClientEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientEvent.Merge(dst, src)
}
func (m *ClientEvent) XXX_Size() int {
	return xxx_messageInfo_ClientEvent.Size(m)
}
func (m *ClientEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientEvent.DiscardUnknown(m)
}

var xxx_messageInfo_ClientEvent proto.InternalMessageInfo

func (m *ClientEvent) GetRequestId() string {
	if m != nil {
		return m.RequestId
	}
	return ""
}

func (m *ClientEvent) GetEventId() string {
	if m != nil {
		return m.EventId
	}
	return ""
}

func (m *ClientEvent) GetCreateTime() *timestamp.Timestamp {
	if m != nil {
		return m.CreateTime
	}
	return nil
}

type isClientEvent_Event interface {
	isClientEvent_Event()
}

type ClientEvent_JobEvent struct {
	JobEvent *JobEvent `protobuf:"bytes,5,opt,name=job_event,json=jobEvent,proto3,oneof"`
}

type ClientEvent_ProfileEvent struct {
	ProfileEvent *ProfileEvent `protobuf:"bytes,6,opt,name=profile_event,json=profileEvent,proto3,oneof"`
}

func (*ClientEvent_JobEvent) isClientEvent_Event() {}

func (*ClientEvent_ProfileEvent) isClientEvent_Event() {}

func (m *ClientEvent) GetEvent() isClientEvent_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (m *ClientEvent) GetJobEvent() *JobEvent {
	if x, ok := m.GetEvent().(*ClientEvent_JobEvent); ok {
		return x.JobEvent
	}
	return nil
}

func (m *ClientEvent) GetProfileEvent() *ProfileEvent {
	if x, ok := m.GetEvent().(*ClientEvent_ProfileEvent); ok {
		return x.ProfileEvent
	}
	return nil
}

func (m *ClientEvent) GetEventNotes() string {
	if m != nil {
		return m.EventNotes
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*ClientEvent) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _ClientEvent_OneofMarshaler, _ClientEvent_OneofUnmarshaler, _ClientEvent_OneofSizer, []interface{}{
		(*ClientEvent_JobEvent)(nil),
		(*ClientEvent_ProfileEvent)(nil),
	}
}

func _ClientEvent_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*ClientEvent)
	// event
	switch x := m.Event.(type) {
	case *ClientEvent_JobEvent:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.JobEvent); err != nil {
			return err
		}
	case *ClientEvent_ProfileEvent:
		b.EncodeVarint(6<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ProfileEvent); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("ClientEvent.Event has unexpected type %T", x)
	}
	return nil
}

func _ClientEvent_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*ClientEvent)
	switch tag {
	case 5: // event.job_event
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(JobEvent)
		err := b.DecodeMessage(msg)
		m.Event = &ClientEvent_JobEvent{msg}
		return true, err
	case 6: // event.profile_event
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(ProfileEvent)
		err := b.DecodeMessage(msg)
		m.Event = &ClientEvent_ProfileEvent{msg}
		return true, err
	default:
		return false, nil
	}
}

func _ClientEvent_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*ClientEvent)
	// event
	switch x := m.Event.(type) {
	case *ClientEvent_JobEvent:
		s := proto.Size(x.JobEvent)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *ClientEvent_ProfileEvent:
		s := proto.Size(x.ProfileEvent)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// An event issued when a job seeker interacts with the application that
// implements Cloud Talent Solution.
type JobEvent struct {
	// Required.
	//
	// The type of the event (see [JobEventType][google.cloud.talent.v4beta1.JobEvent.JobEventType]).
	Type JobEvent_JobEventType `protobuf:"varint,1,opt,name=type,proto3,enum=google.cloud.talent.v4beta1.JobEvent_JobEventType" json:"type,omitempty"`
	// Required.
	//
	// The [job name(s)][google.cloud.talent.v4beta1.Job.name] associated with this event.
	// For example, if this is an [impression][google.cloud.talent.v4beta1.JobEvent.JobEventType.IMPRESSION] event,
	// this field contains the identifiers of all jobs shown to the job seeker.
	// If this was a [view][google.cloud.talent.v4beta1.JobEvent.JobEventType.VIEW] event, this field contains the
	// identifier of the viewed job.
	Jobs                 []string `protobuf:"bytes,2,rep,name=jobs,proto3" json:"jobs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *JobEvent) Reset()         { *m = JobEvent{} }
func (m *JobEvent) String() string { return proto.CompactTextString(m) }
func (*JobEvent) ProtoMessage()    {}
func (*JobEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_event_63120bd8ed2e89e0, []int{1}
}
func (m *JobEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_JobEvent.Unmarshal(m, b)
}
func (m *JobEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_JobEvent.Marshal(b, m, deterministic)
}
func (dst *JobEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_JobEvent.Merge(dst, src)
}
func (m *JobEvent) XXX_Size() int {
	return xxx_messageInfo_JobEvent.Size(m)
}
func (m *JobEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_JobEvent.DiscardUnknown(m)
}

var xxx_messageInfo_JobEvent proto.InternalMessageInfo

func (m *JobEvent) GetType() JobEvent_JobEventType {
	if m != nil {
		return m.Type
	}
	return JobEvent_JOB_EVENT_TYPE_UNSPECIFIED
}

func (m *JobEvent) GetJobs() []string {
	if m != nil {
		return m.Jobs
	}
	return nil
}

// An event issued when a profile searcher interacts with the application
// that implements Cloud Talent Solution.
type ProfileEvent struct {
	// Required.
	//
	// Type of event.
	Type ProfileEvent_ProfileEventType `protobuf:"varint,1,opt,name=type,proto3,enum=google.cloud.talent.v4beta1.ProfileEvent_ProfileEventType" json:"type,omitempty"`
	// Required.
	//
	// The [profile name(s)][google.cloud.talent.v4beta1.Profile.name] associated with this client event.
	Profiles []string `protobuf:"bytes,2,rep,name=profiles,proto3" json:"profiles,omitempty"`
	// Optional.
	//
	// The job ID associated with this client event if there is one. Leave it
	// empty if the event isn't associated with a job.
	//
	// The job ID should be consistent with the
	// [JobApplication.job.requisition_id][] in the profile.
	Jobs                 []string `protobuf:"bytes,6,rep,name=jobs,proto3" json:"jobs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProfileEvent) Reset()         { *m = ProfileEvent{} }
func (m *ProfileEvent) String() string { return proto.CompactTextString(m) }
func (*ProfileEvent) ProtoMessage()    {}
func (*ProfileEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_event_63120bd8ed2e89e0, []int{2}
}
func (m *ProfileEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProfileEvent.Unmarshal(m, b)
}
func (m *ProfileEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProfileEvent.Marshal(b, m, deterministic)
}
func (dst *ProfileEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProfileEvent.Merge(dst, src)
}
func (m *ProfileEvent) XXX_Size() int {
	return xxx_messageInfo_ProfileEvent.Size(m)
}
func (m *ProfileEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_ProfileEvent.DiscardUnknown(m)
}

var xxx_messageInfo_ProfileEvent proto.InternalMessageInfo

func (m *ProfileEvent) GetType() ProfileEvent_ProfileEventType {
	if m != nil {
		return m.Type
	}
	return ProfileEvent_PROFILE_EVENT_TYPE_UNSPECIFIED
}

func (m *ProfileEvent) GetProfiles() []string {
	if m != nil {
		return m.Profiles
	}
	return nil
}

func (m *ProfileEvent) GetJobs() []string {
	if m != nil {
		return m.Jobs
	}
	return nil
}

func init() {
	proto.RegisterType((*ClientEvent)(nil), "google.cloud.talent.v4beta1.ClientEvent")
	proto.RegisterType((*JobEvent)(nil), "google.cloud.talent.v4beta1.JobEvent")
	proto.RegisterType((*ProfileEvent)(nil), "google.cloud.talent.v4beta1.ProfileEvent")
	proto.RegisterEnum("google.cloud.talent.v4beta1.JobEvent_JobEventType", JobEvent_JobEventType_name, JobEvent_JobEventType_value)
	proto.RegisterEnum("google.cloud.talent.v4beta1.ProfileEvent_ProfileEventType", ProfileEvent_ProfileEventType_name, ProfileEvent_ProfileEventType_value)
}

func init() {
	proto.RegisterFile("google/cloud/talent/v4beta1/event.proto", fileDescriptor_event_63120bd8ed2e89e0)
}

var fileDescriptor_event_63120bd8ed2e89e0 = []byte{
	// 682 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x54, 0xdd, 0x6e, 0xd3, 0x4c,
	0x10, 0x6d, 0xfe, 0x93, 0x49, 0x9a, 0x6f, 0xbb, 0xfa, 0x40, 0x21, 0xf4, 0x27, 0x44, 0x20, 0xca,
	0x8d, 0x2d, 0x0a, 0x57, 0xf4, 0xca, 0x71, 0x36, 0x64, 0xdb, 0xc6, 0x36, 0x6b, 0xb7, 0xa8, 0x5c,
	0x60, 0x39, 0xcd, 0x36, 0x72, 0x95, 0x7a, 0x4d, 0xe2, 0x56, 0xf4, 0x35, 0x78, 0x04, 0x1e, 0x86,
	0xc7, 0xe1, 0x05, 0xb8, 0x41, 0x5e, 0x3b, 0x91, 0x0b, 0x55, 0x55, 0x71, 0xb7, 0x33, 0x73, 0xe6,
	0xcc, 0x99, 0xd1, 0xb1, 0xe1, 0xe5, 0x54, 0x88, 0xe9, 0x8c, 0xab, 0x67, 0x33, 0x71, 0x35, 0x51,
	0x23, 0x6f, 0xc6, 0x83, 0x48, 0xbd, 0x7e, 0x3b, 0xe6, 0x91, 0xf7, 0x5a, 0xe5, 0xd7, 0x3c, 0x88,
	0x94, 0x70, 0x2e, 0x22, 0x81, 0x9f, 0x26, 0x40, 0x45, 0x02, 0x95, 0x04, 0xa8, 0xa4, 0xc0, 0xf6,
	0x66, 0xca, 0xe2, 0x85, 0xbe, 0xea, 0x05, 0x81, 0x88, 0xbc, 0xc8, 0x17, 0xc1, 0x22, 0x69, 0x6d,
	0xef, 0xa4, 0x55, 0x19, 0x8d, 0xaf, 0xce, 0xd5, 0xc8, 0xbf, 0xe4, 0x8b, 0xc8, 0xbb, 0x0c, 0x13,
	0x40, 0xf7, 0x47, 0x1e, 0xea, 0xfa, 0xcc, 0xe7, 0x41, 0x44, 0xe2, 0x89, 0x78, 0x0b, 0x60, 0xce,
	0xbf, 0x5c, 0xf1, 0x45, 0xe4, 0xfa, 0x93, 0x56, 0xae, 0x93, 0xdb, 0xad, 0xb1, 0x5a, 0x9a, 0xa1,
	0x13, 0xfc, 0x04, 0xaa, 0x52, 0x59, 0x5c, 0xcc, 0xcb, 0x62, 0x45, 0xc6, 0x74, 0x82, 0xf7, 0xa1,
	0x7e, 0x36, 0xe7, 0x5e, 0xc4, 0xdd, 0x78, 0x46, 0xab, 0xd8, 0xc9, 0xed, 0xd6, 0xf7, 0xda, 0x4a,
	0xaa, 0x7d, 0x29, 0x40, 0x71, 0x96, 0x02, 0x18, 0x24, 0xf0, 0x38, 0x81, 0xfb, 0x50, 0xbb, 0x10,
	0x63, 0x57, 0x72, 0xb5, 0x4a, 0xb2, 0xf5, 0x85, 0x72, 0xcf, 0xda, 0xca, 0x81, 0x18, 0x4b, 0xc1,
	0xc3, 0x35, 0x56, 0xbd, 0x48, 0xdf, 0xd8, 0x82, 0xf5, 0x70, 0x2e, 0xce, 0xfd, 0x19, 0x4f, 0x99,
	0xca, 0x92, 0xe9, 0xd5, 0xbd, 0x4c, 0x56, 0xd2, 0xb1, 0x64, 0x6b, 0x84, 0x99, 0x18, 0xef, 0x40,
	0x3d, 0xd9, 0x37, 0x10, 0x11, 0x5f, 0xb4, 0x6a, 0x72, 0x65, 0x90, 0x29, 0x23, 0xce, 0xf4, 0x2a,
	0x50, 0x92, 0x51, 0xf7, 0x57, 0x01, 0xaa, 0x4b, 0x51, 0x78, 0x00, 0xc5, 0xe8, 0x26, 0xe4, 0xf2,
	0x7e, 0xcd, 0xbd, 0xbd, 0x07, 0x6d, 0xb2, 0x7a, 0x38, 0x37, 0x21, 0x67, 0xb2, 0x1f, 0x63, 0x28,
	0x5e, 0x88, 0xf1, 0xa2, 0x95, 0xef, 0x14, 0x76, 0x6b, 0x4c, 0xbe, 0xbb, 0xdf, 0x0a, 0xd0, 0xc8,
	0x42, 0xf1, 0x36, 0xb4, 0x0f, 0xcc, 0x9e, 0x4b, 0x4e, 0x88, 0xe1, 0xb8, 0xce, 0xa9, 0x45, 0xdc,
	0x63, 0xc3, 0xb6, 0x88, 0x4e, 0x07, 0x94, 0xf4, 0xd1, 0x1a, 0x6e, 0x02, 0xd0, 0x91, 0xc5, 0x88,
	0x6d, 0x53, 0xd3, 0x40, 0x39, 0x5c, 0x85, 0xe2, 0x09, 0x25, 0x1f, 0x51, 0x1e, 0x6f, 0xc0, 0x7a,
	0xfc, 0x72, 0x19, 0xe9, 0x53, 0x46, 0x74, 0x07, 0x15, 0xf0, 0x23, 0xd8, 0xd0, 0x2c, 0xeb, 0x88,
	0xea, 0x9a, 0x43, 0x4d, 0xc3, 0xb5, 0x1d, 0x8d, 0x39, 0xa8, 0x88, 0x1f, 0x03, 0xce, 0xa6, 0x07,
	0xd4, 0xa0, 0xf6, 0x10, 0x95, 0x70, 0x07, 0x36, 0xb3, 0xf9, 0x0f, 0xc7, 0x54, 0x3f, 0x74, 0xed,
	0xe3, 0xde, 0x88, 0x26, 0xd3, 0xca, 0xb8, 0x05, 0xff, 0x67, 0x11, 0xab, 0x51, 0x15, 0xfc, 0x0c,
	0xb6, 0xfe, 0x1a, 0xe5, 0x0e, 0x98, 0x39, 0x72, 0x6d, 0xa2, 0x31, 0x7d, 0x88, 0xaa, 0xf8, 0x39,
	0x74, 0xee, 0x6a, 0xbe, 0x85, 0xaa, 0xc5, 0x07, 0xc8, 0xa2, 0x74, 0x73, 0x64, 0x69, 0xc6, 0x69,
	0x22, 0xc3, 0x41, 0x80, 0x1b, 0x50, 0xed, 0x99, 0xe6, 0xe1, 0x48, 0x63, 0x87, 0xa8, 0x8e, 0x11,
	0x34, 0x0c, 0xd3, 0xa1, 0x83, 0x14, 0x8e, 0x1a, 0xb8, 0x06, 0xa5, 0x21, 0x65, 0xa4, 0x8f, 0xd6,
	0x71, 0x1d, 0x2a, 0x76, 0x7c, 0x46, 0xfd, 0x04, 0x35, 0xe3, 0x5b, 0x50, 0xc3, 0x21, 0x4c, 0xde,
	0xe8, 0x3d, 0xd3, 0x0c, 0x87, 0xf4, 0xd1, 0x7f, 0x18, 0x43, 0xd3, 0x30, 0x1d, 0x57, 0x96, 0x88,
	0x1d, 0xe7, 0x50, 0xf7, 0x67, 0x0e, 0x1a, 0x59, 0x23, 0x61, 0xe3, 0x96, 0x03, 0xde, 0x3d, 0xd8,
	0x81, 0xb7, 0x82, 0x8c, 0x13, 0xda, 0x50, 0x4d, 0x8d, 0xb9, 0x74, 0xc3, 0x2a, 0x5e, 0xb9, 0xa4,
	0x9c, 0x71, 0xc9, 0x67, 0x40, 0x7f, 0x32, 0xe1, 0x2e, 0x6c, 0x5b, 0xcc, 0x1c, 0xd0, 0x23, 0xf2,
	0x2f, 0x66, 0xc9, 0x5e, 0xb1, 0xd0, 0xfb, 0x0a, 0x3b, 0x67, 0xe2, 0xf2, 0xbe, 0xb5, 0x7a, 0x20,
	0x27, 0x5b, 0xf1, 0x87, 0x6f, 0xe5, 0x3e, 0x69, 0x29, 0x74, 0x2a, 0x66, 0x5e, 0x30, 0x55, 0xc4,
	0x7c, 0xaa, 0x4e, 0x79, 0x20, 0x7f, 0x0b, 0x6a, 0x52, 0xf2, 0x42, 0x7f, 0x71, 0xe7, 0xcf, 0x70,
	0x3f, 0x09, 0xbf, 0xe7, 0x0b, 0xba, 0x63, 0x8f, 0xcb, 0xb2, 0xe7, 0xcd, 0xef, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x6c, 0x1e, 0x6f, 0x92, 0x3f, 0x05, 0x00, 0x00,
}
