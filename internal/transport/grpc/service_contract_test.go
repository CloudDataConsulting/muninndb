//go:build grpcwire

package grpc_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestGeneratedDescriptor_FrozenMessageFields(t *testing.T) {
	want := map[string][]string{
		"HelloRequest": {
			"version=1/string/optional", "auth_method=2/string/optional",
			"token=3/string/optional", "vault=4/string/optional",
			"client=5/string/optional", "capabilities=6/string/repeated",
		},
		"HelloResponse": {
			"server_version=1/string/optional", "session_id=2/string/optional",
			"vault_id=3/string/optional", "capabilities=4/string/repeated",
			"limits=5/message:muninn.v1.Limits/optional",
		},
		"Limits": {
			"max_results=1/int32/optional", "max_hop_depth=2/int32/optional",
			"max_rate=3/int32/optional", "max_payload_mb=4/int32/optional",
		},
		"WriteRequest": {
			"concept=1/string/optional", "content=2/string/optional",
			"tags=3/string/repeated", "confidence=4/float/optional",
			"stability=5/float/optional", "vault=6/string/optional",
			"idempotent_id=7/string/optional",
			"associations=8/message:muninn.v1.Association/repeated",
			"embedding=9/float/repeated", "memory_type=10/uint32/optional",
			"type_label=11/string/optional",
		},
		"WriteResponse": {
			"id=1/string/optional", "created_at=2/int64/optional",
		},
		"BatchWriteRequest": {
			"requests=1/message:muninn.v1.WriteRequest/repeated",
		},
		"BatchWriteItemResult": {
			"index=1/int32/optional", "id=2/string/optional", "error=3/string/optional",
		},
		"BatchWriteResponse": {
			"results=1/message:muninn.v1.BatchWriteItemResult/repeated",
		},
		"ReadRequest": {
			"id=1/string/optional", "vault=2/string/optional",
		},
		"ReadResponse": {
			"id=1/string/optional", "concept=2/string/optional",
			"content=3/string/optional", "confidence=4/float/optional",
			"relevance=5/float/optional", "tags=6/string/repeated",
			"state=7/uint32/optional", "created_at=8/int64/optional",
			"updated_at=9/int64/optional", "last_access=10/int64/optional",
			"access_count=11/uint32/optional", "stability=12/float/optional",
			"memory_type=13/uint32/optional", "type_label=14/string/optional",
		},
		"ForgetRequest": {
			"id=1/string/optional", "hard=2/bool/optional", "vault=3/string/optional",
		},
		"ForgetResponse": {"ok=1/bool/optional"},
		"StatRequest":    {"vault=1/string/optional"},
		"StatResponse": {
			"engram_count=1/int64/optional", "storage_bytes=2/int64/optional",
			"vault_count=3/int32/optional", "index_size=4/int64/optional",
		},
		"LinkRequest": {
			"source_id=1/string/optional", "target_id=2/string/optional",
			"rel_type=3/uint32/optional", "weight=4/float/optional",
			"vault=5/string/optional",
		},
		"LinkResponse": {"ok=1/bool/optional"},
		"Association": {
			"target_id=1/string/optional", "rel_type=2/uint32/optional",
			"weight=3/float/optional", "confidence=4/float/optional",
			"created_at=5/int64/optional", "last_activated=6/int32/optional",
		},
		"ActivateRequest": {
			"context=1/string/repeated", "threshold=2/float/optional",
			"max_results=3/int32/optional", "max_hops=4/int32/optional",
			"include_why=5/bool/optional", "vault=6/string/optional",
			"weights=7/message:muninn.v1.Weights/optional",
			"filters=8/message:muninn.v1.Filter/repeated",
			"embedding=9/float/repeated",
		},
		"Weights": {
			"semantic_similarity=1/float/optional", "full_text_relevance=2/float/optional",
			"decay_factor=3/float/optional", "hebbian_boost=4/float/optional",
			"access_frequency=5/float/optional", "recency=6/float/optional",
		},
		"Filter": {
			"field=1/string/optional", "op=2/string/optional", "value=3/bytes/optional",
		},
		"ActivateResponse": {
			"query_id=1/string/optional", "total_found=2/int32/optional",
			"activations=3/message:muninn.v1.ActivationItem/repeated",
			"latency_ms=4/double/optional", "frame=5/int32/optional",
			"total_frames=6/int32/optional",
		},
		"ActivationItem": {
			"id=1/string/optional", "concept=2/string/optional",
			"content=3/string/optional", "score=4/float/optional",
			"confidence=5/float/optional",
			"score_components=6/message:muninn.v1.ScoreComponents/optional",
			"why=7/string/optional", "hop_path=8/string/repeated",
			"dormant=9/bool/optional",
		},
		"ScoreComponents": {
			"semantic_similarity=1/float/optional", "full_text_relevance=2/float/optional",
			"decay_factor=3/float/optional", "hebbian_boost=4/float/optional",
			"access_frequency=5/float/optional", "recency=6/float/optional",
			"raw=7/float/optional", "final=8/float/optional",
		},
		"SubscribeRequest": {
			"subscription_id=1/string/optional", "context=2/string/repeated",
			"threshold=3/float/optional", "vault=4/string/optional",
			"ttl=5/int32/optional", "rate_limit=6/int32/optional",
			"push_on_write=7/bool/optional", "delta_threshold=8/float/optional",
		},
		"SubscribeResponse": {
			"sub_id=1/string/optional", "status=2/string/optional",
		},
		"ActivationPush": {
			"subscription_id=1/string/optional",
			"activation=2/message:muninn.v1.ActivationItem/optional",
			"trigger=3/string/optional", "push_number=4/int32/optional",
			"at=5/int64/optional",
		},
	}

	file := pb.File_muninn_v1_service_proto
	if got := file.Path(); got != "muninn/v1/service.proto" {
		t.Fatalf("descriptor path = %q", got)
	}
	if got := string(file.Package()); got != "muninn.v1" {
		t.Fatalf("descriptor package = %q", got)
	}
	opts, ok := file.Options().(*descriptorpb.FileOptions)
	if !ok {
		t.Fatalf("file options type = %T", file.Options())
	}
	if got := opts.GetGoPackage(); got != "github.com/scrypster/muninndb/proto/gen/go/muninn/v1;muninn_v1" {
		t.Fatalf("go_package = %q", got)
	}

	messages := file.Messages()
	if messages.Len() != len(want) {
		t.Fatalf("message count = %d, want %d", messages.Len(), len(want))
	}
	for name, wantFields := range want {
		message := messages.ByName(protoreflect.Name(name))
		if message == nil {
			t.Errorf("missing message %s", name)
			continue
		}
		if got := fieldSignatures(message); !reflect.DeepEqual(got, wantFields) {
			t.Errorf("%s fields:\n got %v\nwant %v", name, got, wantFields)
		}
	}
}

func TestGeneratedDescriptor_FrozenRPCPathsAndStreamingShapes(t *testing.T) {
	want := map[string]struct {
		input, output        protoreflect.FullName
		client, serverStream bool
		path                 string
	}{
		"Hello":      {"muninn.v1.HelloRequest", "muninn.v1.HelloResponse", false, false, "/muninn.v1.MuninnDB/Hello"},
		"Write":      {"muninn.v1.WriteRequest", "muninn.v1.WriteResponse", false, false, "/muninn.v1.MuninnDB/Write"},
		"BatchWrite": {"muninn.v1.BatchWriteRequest", "muninn.v1.BatchWriteResponse", false, false, "/muninn.v1.MuninnDB/BatchWrite"},
		"Read":       {"muninn.v1.ReadRequest", "muninn.v1.ReadResponse", false, false, "/muninn.v1.MuninnDB/Read"},
		"Forget":     {"muninn.v1.ForgetRequest", "muninn.v1.ForgetResponse", false, false, "/muninn.v1.MuninnDB/Forget"},
		"Stat":       {"muninn.v1.StatRequest", "muninn.v1.StatResponse", false, false, "/muninn.v1.MuninnDB/Stat"},
		"Link":       {"muninn.v1.LinkRequest", "muninn.v1.LinkResponse", false, false, "/muninn.v1.MuninnDB/Link"},
		"Activate":   {"muninn.v1.ActivateRequest", "muninn.v1.ActivateResponse", false, true, "/muninn.v1.MuninnDB/Activate"},
		"Subscribe":  {"muninn.v1.SubscribeRequest", "muninn.v1.ActivationPush", true, true, "/muninn.v1.MuninnDB/Subscribe"},
	}
	paths := map[string]string{
		"Hello": pb.MuninnDB_Hello_FullMethodName, "Write": pb.MuninnDB_Write_FullMethodName,
		"BatchWrite": pb.MuninnDB_BatchWrite_FullMethodName, "Read": pb.MuninnDB_Read_FullMethodName,
		"Forget": pb.MuninnDB_Forget_FullMethodName, "Stat": pb.MuninnDB_Stat_FullMethodName,
		"Link": pb.MuninnDB_Link_FullMethodName, "Activate": pb.MuninnDB_Activate_FullMethodName,
		"Subscribe": pb.MuninnDB_Subscribe_FullMethodName,
	}

	services := pb.File_muninn_v1_service_proto.Services()
	if services.Len() != 1 {
		t.Fatalf("service count = %d, want 1", services.Len())
	}
	service := services.Get(0)
	if got := string(service.FullName()); got != "muninn.v1.MuninnDB" {
		t.Fatalf("service name = %q", got)
	}
	if service.Methods().Len() != len(want) {
		t.Fatalf("method count = %d, want %d", service.Methods().Len(), len(want))
	}
	for name, expected := range want {
		method := service.Methods().ByName(protoreflect.Name(name))
		if method == nil {
			t.Errorf("missing method %s", name)
			continue
		}
		if method.Input().FullName() != expected.input || method.Output().FullName() != expected.output {
			t.Errorf("%s types = %s -> %s", name, method.Input().FullName(), method.Output().FullName())
		}
		if method.IsStreamingClient() != expected.client || method.IsStreamingServer() != expected.serverStream {
			t.Errorf("%s streaming = client:%t server:%t", name, method.IsStreamingClient(), method.IsStreamingServer())
		}
		if got := paths[name]; got != expected.path {
			t.Errorf("%s generated path = %q, want %q", name, got, expected.path)
		}
	}
}

func fieldSignatures(message protoreflect.MessageDescriptor) []string {
	fields := message.Fields()
	result := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		kind := field.Kind().String()
		if field.Kind() == protoreflect.MessageKind {
			kind += ":" + string(field.Message().FullName())
		}
		result = append(result, fmt.Sprintf(
			"%s=%d/%s/%s",
			field.Name(), field.Number(), kind, strings.ToLower(field.Cardinality().String()),
		))
	}
	return result
}
