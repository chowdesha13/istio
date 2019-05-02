// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/cloud/automl/v1beta1/text_sentiment.proto

package automl // import "google.golang.org/genproto/googleapis/cloud/automl/v1beta1"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
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

// Contains annotation details specific to text sentiment.
type TextSentimentAnnotation struct {
	// Output only. The sentiment with the semantic, as given to the
	// [AutoMl.ImportData][google.cloud.automl.v1beta1.AutoMl.ImportData] when populating the dataset from which the model used
	// for the prediction had been trained.
	// The sentiment values are between 0 and
	// Dataset.text_sentiment_dataset_metadata.sentiment_max (inclusive),
	// with higher value meaning more positive sentiment. They are completely
	// relative, i.e. 0 means least positive sentiment and sentiment_max means
	// the most positive from the sentiments present in the train data. Therefore
	//  e.g. if train data had only negative sentiment, then sentiment_max, would
	// be still negative (although least negative).
	// The sentiment shouldn't be confused with "score" or "magnitude"
	// from the previous Natural Language Sentiment Analysis API.
	Sentiment            int32    `protobuf:"varint,1,opt,name=sentiment,proto3" json:"sentiment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TextSentimentAnnotation) Reset()         { *m = TextSentimentAnnotation{} }
func (m *TextSentimentAnnotation) String() string { return proto.CompactTextString(m) }
func (*TextSentimentAnnotation) ProtoMessage()    {}
func (*TextSentimentAnnotation) Descriptor() ([]byte, []int) {
	return fileDescriptor_text_sentiment_33b9f472f0a7750f, []int{0}
}
func (m *TextSentimentAnnotation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TextSentimentAnnotation.Unmarshal(m, b)
}
func (m *TextSentimentAnnotation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TextSentimentAnnotation.Marshal(b, m, deterministic)
}
func (dst *TextSentimentAnnotation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TextSentimentAnnotation.Merge(dst, src)
}
func (m *TextSentimentAnnotation) XXX_Size() int {
	return xxx_messageInfo_TextSentimentAnnotation.Size(m)
}
func (m *TextSentimentAnnotation) XXX_DiscardUnknown() {
	xxx_messageInfo_TextSentimentAnnotation.DiscardUnknown(m)
}

var xxx_messageInfo_TextSentimentAnnotation proto.InternalMessageInfo

func (m *TextSentimentAnnotation) GetSentiment() int32 {
	if m != nil {
		return m.Sentiment
	}
	return 0
}

// Model evaluation metrics for text sentiment problems.
type TextSentimentEvaluationMetrics struct {
	// Output only. Precision.
	Precision float32 `protobuf:"fixed32,1,opt,name=precision,proto3" json:"precision,omitempty"`
	// Output only. Recall.
	Recall float32 `protobuf:"fixed32,2,opt,name=recall,proto3" json:"recall,omitempty"`
	// Output only. The harmonic mean of recall and precision.
	F1Score float32 `protobuf:"fixed32,3,opt,name=f1_score,json=f1Score,proto3" json:"f1_score,omitempty"`
	// Output only. Mean absolute error. Only set for the overall model
	// evaluation, not for evaluation of a single annotation spec.
	MeanAbsoluteError float32 `protobuf:"fixed32,4,opt,name=mean_absolute_error,json=meanAbsoluteError,proto3" json:"mean_absolute_error,omitempty"`
	// Output only. Mean squared error. Only set for the overall model
	// evaluation, not for evaluation of a single annotation spec.
	MeanSquaredError float32 `protobuf:"fixed32,5,opt,name=mean_squared_error,json=meanSquaredError,proto3" json:"mean_squared_error,omitempty"`
	// Output only. Linear weighted kappa. Only set for the overall model
	// evaluation, not for evaluation of a single annotation spec.
	LinearKappa float32 `protobuf:"fixed32,6,opt,name=linear_kappa,json=linearKappa,proto3" json:"linear_kappa,omitempty"`
	// Output only. Quadratic weighted kappa. Only set for the overall model
	// evaluation, not for evaluation of a single annotation spec.
	QuadraticKappa float32 `protobuf:"fixed32,7,opt,name=quadratic_kappa,json=quadraticKappa,proto3" json:"quadratic_kappa,omitempty"`
	// Output only. Confusion matrix of the evaluation.
	// Only set for the overall model evaluation, not for evaluation of a single
	// annotation spec.
	ConfusionMatrix *ClassificationEvaluationMetrics_ConfusionMatrix `protobuf:"bytes,8,opt,name=confusion_matrix,json=confusionMatrix,proto3" json:"confusion_matrix,omitempty"`
	// Output only. The annotation spec ids used for this evaluation.
	// Deprecated, remove after Boq Migration and use then
	// TextSentimentModelMetadata.annotation_spec_count for count, and list
	// all model evaluations to see the exact annotation_spec_ids that were
	// used.
	AnnotationSpecId     []string `protobuf:"bytes,9,rep,name=annotation_spec_id,json=annotationSpecId,proto3" json:"annotation_spec_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TextSentimentEvaluationMetrics) Reset()         { *m = TextSentimentEvaluationMetrics{} }
func (m *TextSentimentEvaluationMetrics) String() string { return proto.CompactTextString(m) }
func (*TextSentimentEvaluationMetrics) ProtoMessage()    {}
func (*TextSentimentEvaluationMetrics) Descriptor() ([]byte, []int) {
	return fileDescriptor_text_sentiment_33b9f472f0a7750f, []int{1}
}
func (m *TextSentimentEvaluationMetrics) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TextSentimentEvaluationMetrics.Unmarshal(m, b)
}
func (m *TextSentimentEvaluationMetrics) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TextSentimentEvaluationMetrics.Marshal(b, m, deterministic)
}
func (dst *TextSentimentEvaluationMetrics) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TextSentimentEvaluationMetrics.Merge(dst, src)
}
func (m *TextSentimentEvaluationMetrics) XXX_Size() int {
	return xxx_messageInfo_TextSentimentEvaluationMetrics.Size(m)
}
func (m *TextSentimentEvaluationMetrics) XXX_DiscardUnknown() {
	xxx_messageInfo_TextSentimentEvaluationMetrics.DiscardUnknown(m)
}

var xxx_messageInfo_TextSentimentEvaluationMetrics proto.InternalMessageInfo

func (m *TextSentimentEvaluationMetrics) GetPrecision() float32 {
	if m != nil {
		return m.Precision
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetRecall() float32 {
	if m != nil {
		return m.Recall
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetF1Score() float32 {
	if m != nil {
		return m.F1Score
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetMeanAbsoluteError() float32 {
	if m != nil {
		return m.MeanAbsoluteError
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetMeanSquaredError() float32 {
	if m != nil {
		return m.MeanSquaredError
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetLinearKappa() float32 {
	if m != nil {
		return m.LinearKappa
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetQuadraticKappa() float32 {
	if m != nil {
		return m.QuadraticKappa
	}
	return 0
}

func (m *TextSentimentEvaluationMetrics) GetConfusionMatrix() *ClassificationEvaluationMetrics_ConfusionMatrix {
	if m != nil {
		return m.ConfusionMatrix
	}
	return nil
}

func (m *TextSentimentEvaluationMetrics) GetAnnotationSpecId() []string {
	if m != nil {
		return m.AnnotationSpecId
	}
	return nil
}

func init() {
	proto.RegisterType((*TextSentimentAnnotation)(nil), "google.cloud.automl.v1beta1.TextSentimentAnnotation")
	proto.RegisterType((*TextSentimentEvaluationMetrics)(nil), "google.cloud.automl.v1beta1.TextSentimentEvaluationMetrics")
}

func init() {
	proto.RegisterFile("google/cloud/automl/v1beta1/text_sentiment.proto", fileDescriptor_text_sentiment_33b9f472f0a7750f)
}

var fileDescriptor_text_sentiment_33b9f472f0a7750f = []byte{
	// 452 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0x41, 0x6f, 0x13, 0x31,
	0x10, 0x85, 0x95, 0x84, 0xa6, 0x8d, 0x8b, 0x68, 0x30, 0x12, 0x2c, 0x6d, 0x05, 0xa1, 0x17, 0x72,
	0x40, 0x5e, 0x02, 0x07, 0x0e, 0x9c, 0xd2, 0xa8, 0x42, 0x08, 0x22, 0xa1, 0x04, 0x71, 0x40, 0x91,
	0x56, 0x13, 0xef, 0x64, 0x65, 0xe1, 0xb5, 0xb7, 0xb6, 0xb7, 0xe4, 0x97, 0xf0, 0x83, 0x38, 0xf2,
	0xab, 0x90, 0xed, 0x4d, 0xa2, 0x08, 0x94, 0xa3, 0xdf, 0xfb, 0xde, 0x5b, 0x7b, 0x67, 0xc8, 0xeb,
	0x42, 0xeb, 0x42, 0x62, 0xca, 0xa5, 0xae, 0xf3, 0x14, 0x6a, 0xa7, 0x4b, 0x99, 0xde, 0x8d, 0x96,
	0xe8, 0x60, 0x94, 0x3a, 0x5c, 0xbb, 0xcc, 0xa2, 0x72, 0xa2, 0x44, 0xe5, 0x58, 0x65, 0xb4, 0xd3,
	0xf4, 0x22, 0x26, 0x58, 0x48, 0xb0, 0x98, 0x60, 0x4d, 0xe2, 0xfc, 0xb2, 0xa9, 0x83, 0x4a, 0xa4,
	0xa0, 0x94, 0x76, 0xe0, 0x84, 0x56, 0x36, 0x46, 0xcf, 0x0f, 0x7e, 0x8c, 0x4b, 0xb0, 0x56, 0xac,
	0x04, 0x0f, 0x91, 0x98, 0xb8, 0x7a, 0x47, 0x9e, 0x7c, 0xc5, 0xb5, 0x9b, 0x6f, 0xee, 0x30, 0xde,
	0x76, 0xd2, 0x4b, 0xd2, 0xdb, 0x5e, 0x2d, 0x69, 0x0d, 0x5a, 0xc3, 0xa3, 0xd9, 0x4e, 0xb8, 0xfa,
	0xdd, 0x21, 0xcf, 0xf6, 0x92, 0x37, 0x77, 0x20, 0xeb, 0x90, 0x9c, 0xa2, 0x33, 0x82, 0x5b, 0x5f,
	0x50, 0x19, 0xe4, 0xc2, 0x0a, 0xad, 0x42, 0x41, 0x7b, 0xb6, 0x13, 0xe8, 0x63, 0xd2, 0x35, 0xc8,
	0x41, 0xca, 0xa4, 0x1d, 0xac, 0xe6, 0x44, 0x9f, 0x92, 0x93, 0xd5, 0x28, 0xb3, 0x5c, 0x1b, 0x4c,
	0x3a, 0xc1, 0x39, 0x5e, 0x8d, 0xe6, 0xfe, 0x48, 0x19, 0x79, 0x54, 0x22, 0xa8, 0x0c, 0x96, 0x56,
	0xcb, 0xda, 0x61, 0x86, 0xc6, 0x68, 0x93, 0xdc, 0x0b, 0xd4, 0x43, 0x6f, 0x8d, 0x1b, 0xe7, 0xc6,
	0x1b, 0xf4, 0x15, 0xa1, 0x81, 0xb7, 0xb7, 0x35, 0x18, 0xcc, 0x1b, 0xfc, 0x28, 0xe0, 0x7d, 0xef,
	0xcc, 0xa3, 0x11, 0xe9, 0x17, 0xe4, 0xbe, 0x14, 0x0a, 0xc1, 0x64, 0x3f, 0xa0, 0xaa, 0x20, 0xe9,
	0x06, 0xee, 0x34, 0x6a, 0x9f, 0xbc, 0x44, 0x5f, 0x92, 0xb3, 0xdb, 0x1a, 0x72, 0x03, 0x4e, 0xf0,
	0x86, 0x3a, 0x0e, 0xd4, 0x83, 0xad, 0x1c, 0xc1, 0x9f, 0xa4, 0xcf, 0xb5, 0x5a, 0xd5, 0xfe, 0xa5,
	0x59, 0x09, 0xce, 0x88, 0x75, 0x72, 0x32, 0x68, 0x0d, 0x4f, 0xdf, 0x7c, 0x66, 0x07, 0xc6, 0xcb,
	0x26, 0x7b, 0x33, 0xfa, 0xe7, 0x97, 0xb2, 0xc9, 0xa6, 0x74, 0x1a, 0x3a, 0x67, 0x67, 0x7c, 0x5f,
	0xf0, 0x4f, 0xde, 0xad, 0x45, 0x66, 0x2b, 0xe4, 0x99, 0xc8, 0x93, 0xde, 0xa0, 0x33, 0xec, 0xcd,
	0xfa, 0x3b, 0x67, 0x5e, 0x21, 0xff, 0x98, 0x5f, 0xff, 0x6a, 0x91, 0xe7, 0x5c, 0x97, 0x87, 0xae,
	0x74, 0x4d, 0xf7, 0xa6, 0xfc, 0xc5, 0x6f, 0xcd, 0xf7, 0x71, 0x13, 0x28, 0xb4, 0x04, 0x55, 0x30,
	0x6d, 0x8a, 0xb4, 0x40, 0x15, 0x36, 0x2a, 0x8d, 0x16, 0x54, 0xc2, 0xfe, 0x77, 0x0d, 0xdf, 0xc7,
	0xe3, 0x9f, 0xf6, 0xc5, 0x87, 0x00, 0x2e, 0x26, 0x1e, 0x5a, 0x8c, 0x6b, 0xa7, 0xa7, 0x72, 0xf1,
	0x2d, 0x42, 0xcb, 0x6e, 0xe8, 0x7a, 0xfb, 0x37, 0x00, 0x00, 0xff, 0xff, 0xa7, 0xb8, 0xf3, 0x06,
	0x3e, 0x03, 0x00, 0x00,
}
