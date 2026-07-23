// Code generated manually for MuninnDB. DO NOT EDIT.
//
// These legacy protobuf methods make the hand-written message structs usable
// by grpc-go's default protobuf codec. grpc-go adapts v1 messages to the v2
// reflection API at runtime using the protobuf struct tags in service.pb.go.

package muninn_v1

import (
	"fmt"
	"reflect"
)

func legacyMessageString(message any) string {
	value := reflect.ValueOf(message)
	if !value.IsValid() || (value.Kind() == reflect.Ptr && value.IsNil()) {
		return "<nil>"
	}
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	return fmt.Sprintf("%+v", value.Interface())
}

func (m *HelloRequest) Reset()         { *m = HelloRequest{} }
func (m *HelloRequest) String() string { return legacyMessageString(m) }
func (*HelloRequest) ProtoMessage()    {}

func (m *HelloResponse) Reset()         { *m = HelloResponse{} }
func (m *HelloResponse) String() string { return legacyMessageString(m) }
func (*HelloResponse) ProtoMessage()    {}

func (m *Limits) Reset()         { *m = Limits{} }
func (m *Limits) String() string { return legacyMessageString(m) }
func (*Limits) ProtoMessage()    {}

func (m *WriteRequest) Reset()         { *m = WriteRequest{} }
func (m *WriteRequest) String() string { return legacyMessageString(m) }
func (*WriteRequest) ProtoMessage()    {}

func (m *WriteResponse) Reset()         { *m = WriteResponse{} }
func (m *WriteResponse) String() string { return legacyMessageString(m) }
func (*WriteResponse) ProtoMessage()    {}

func (m *BatchWriteRequest) Reset()         { *m = BatchWriteRequest{} }
func (m *BatchWriteRequest) String() string { return legacyMessageString(m) }
func (*BatchWriteRequest) ProtoMessage()    {}

func (m *BatchWriteItemResult) Reset()         { *m = BatchWriteItemResult{} }
func (m *BatchWriteItemResult) String() string { return legacyMessageString(m) }
func (*BatchWriteItemResult) ProtoMessage()    {}

func (m *BatchWriteResponse) Reset()         { *m = BatchWriteResponse{} }
func (m *BatchWriteResponse) String() string { return legacyMessageString(m) }
func (*BatchWriteResponse) ProtoMessage()    {}

func (m *ReadRequest) Reset()         { *m = ReadRequest{} }
func (m *ReadRequest) String() string { return legacyMessageString(m) }
func (*ReadRequest) ProtoMessage()    {}

func (m *ReadResponse) Reset()         { *m = ReadResponse{} }
func (m *ReadResponse) String() string { return legacyMessageString(m) }
func (*ReadResponse) ProtoMessage()    {}

func (m *ForgetRequest) Reset()         { *m = ForgetRequest{} }
func (m *ForgetRequest) String() string { return legacyMessageString(m) }
func (*ForgetRequest) ProtoMessage()    {}

func (m *ForgetResponse) Reset()         { *m = ForgetResponse{} }
func (m *ForgetResponse) String() string { return legacyMessageString(m) }
func (*ForgetResponse) ProtoMessage()    {}

func (m *StatRequest) Reset()         { *m = StatRequest{} }
func (m *StatRequest) String() string { return legacyMessageString(m) }
func (*StatRequest) ProtoMessage()    {}

func (m *StatResponse) Reset()         { *m = StatResponse{} }
func (m *StatResponse) String() string { return legacyMessageString(m) }
func (*StatResponse) ProtoMessage()    {}

func (m *LinkRequest) Reset()         { *m = LinkRequest{} }
func (m *LinkRequest) String() string { return legacyMessageString(m) }
func (*LinkRequest) ProtoMessage()    {}

func (m *LinkResponse) Reset()         { *m = LinkResponse{} }
func (m *LinkResponse) String() string { return legacyMessageString(m) }
func (*LinkResponse) ProtoMessage()    {}

func (m *Association) Reset()         { *m = Association{} }
func (m *Association) String() string { return legacyMessageString(m) }
func (*Association) ProtoMessage()    {}

func (m *ActivateRequest) Reset()         { *m = ActivateRequest{} }
func (m *ActivateRequest) String() string { return legacyMessageString(m) }
func (*ActivateRequest) ProtoMessage()    {}

func (m *Weights) Reset()         { *m = Weights{} }
func (m *Weights) String() string { return legacyMessageString(m) }
func (*Weights) ProtoMessage()    {}

func (m *Filter) Reset()         { *m = Filter{} }
func (m *Filter) String() string { return legacyMessageString(m) }
func (*Filter) ProtoMessage()    {}

func (m *ActivateResponse) Reset()         { *m = ActivateResponse{} }
func (m *ActivateResponse) String() string { return legacyMessageString(m) }
func (*ActivateResponse) ProtoMessage()    {}

func (m *ActivationItem) Reset()         { *m = ActivationItem{} }
func (m *ActivationItem) String() string { return legacyMessageString(m) }
func (*ActivationItem) ProtoMessage()    {}

func (m *ScoreComponents) Reset()         { *m = ScoreComponents{} }
func (m *ScoreComponents) String() string { return legacyMessageString(m) }
func (*ScoreComponents) ProtoMessage()    {}

func (m *SubscribeRequest) Reset()         { *m = SubscribeRequest{} }
func (m *SubscribeRequest) String() string { return legacyMessageString(m) }
func (*SubscribeRequest) ProtoMessage()    {}

func (m *SubscribeResponse) Reset()         { *m = SubscribeResponse{} }
func (m *SubscribeResponse) String() string { return legacyMessageString(m) }
func (*SubscribeResponse) ProtoMessage()    {}

func (m *ActivationPush) Reset()         { *m = ActivationPush{} }
func (m *ActivationPush) String() string { return legacyMessageString(m) }
func (*ActivationPush) ProtoMessage()    {}
