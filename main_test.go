package main

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/simon-engledew/authkafka/kafkaproto"
)

func TestRecode(t *testing.T) {
	str := func(s string) *string { return &s }

	cases := []struct {
		name    string
		version int16
		req     kafkaproto.MetadataRequest
	}{
		{
			name:    "v0 single topic",
			version: 0,
			req: kafkaproto.MetadataRequest{
				Topics: []kafkaproto.MetadataRequestTopic{
					{Name: str("foo")},
				},
			},
		},
		{
			name:    "v8 with auth-ops flags",
			version: 8,
			req: kafkaproto.MetadataRequest{
				Topics: []kafkaproto.MetadataRequestTopic{
					{Name: str("foo")},
					{Name: str("bar")},
				},
				AllowAutoTopicCreation:             true,
				IncludeClusterAuthorizedOperations: true,
				IncludeTopicAuthorizedOperations:   true,
			},
		},
		{
			name:    "v9 flexible empty",
			version: 9,
			req: kafkaproto.MetadataRequest{
				Topics:                 []kafkaproto.MetadataRequestTopic{},
				AllowAutoTopicCreation: true,
			},
		},
		{
			name:    "v12 with topic id and null name",
			version: 12,
			req: kafkaproto.MetadataRequest{
				Topics: []kafkaproto.MetadataRequestTopic{
					{
						TopicId: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
						Name:    str("with-id"),
					},
					{
						TopicId: [16]byte{0xff, 0xee},
						Name:    nil,
					},
				},
				AllowAutoTopicCreation:           true,
				IncludeTopicAuthorizedOperations: true,
			},
		},
		{
			name:    "v12 null topics",
			version: 12,
			req: kafkaproto.MetadataRequest{
				Topics: nil,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := kafkaproto.NewWriter()
			if err := tc.req.Encode(w, tc.version); err != nil {
				t.Fatalf("Encode: %v", err)
			}

			var got kafkaproto.MetadataRequest
			if err := got.Decode(kafkaproto.NewReader(w.Bytes()), tc.version); err != nil {
				t.Fatalf("Decode: %v", err)
			}

			if !reflect.DeepEqual(tc.req, got) {
				t.Fatalf("roundtrip mismatch\nwant: %#v\n got: %#v", tc.req, got)
			}
		})
	}
}

// TestMetadataResponseV12Roundtrip decodes a captured MetadataResponse v12 wire
// payload and verifies that re-encoding the resulting struct produces the
// exact same bytes. The input starts with the response header
// (correlation_id + flexible tag-buffer); since Decode/Encode operate on the
// body only, those 5 leading bytes are stripped before decode and kept aside
// for the final byte comparison.
func TestMetadataResponseV12Roundtrip(t *testing.T) {
	raw := []byte{
		0, 0, 0, 3, 0, 0, 0, 0, 0, 2, 0, 0, 0, 111, 10, 108, 111, 99, 97, 108,
		104, 111, 115, 116, 0, 0, 35, 132, 0, 0, 14, 116, 97, 110, 115, 117, 95,
		99, 108, 117, 115, 116, 101, 114, 0, 0, 0, 111, 2, 0, 0, 8, 100, 101,
		102, 97, 117, 108, 116, 1, 158, 18, 209, 54, 67, 117, 113, 176, 66, 59,
		137, 174, 99, 21, 150, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 111, 0, 0, 0, 0,
		2, 0, 0, 0, 111, 2, 0, 0, 0, 111, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 111,
		0, 0, 0, 0, 2, 0, 0, 0, 111, 2, 0, 0, 0, 111, 1, 0, 0, 0, 0, 0, 0, 2, 0,
		0, 0, 111, 0, 0, 0, 0, 2, 0, 0, 0, 111, 2, 0, 0, 0, 111, 1, 0, 128, 0,
		0, 0, 0, 0,
	}

	const headerLen = 5 // int32 correlation_id + 1-byte empty tag-buffer

	var resp kafkaproto.MetadataResponse
	if err := resp.Decode(kafkaproto.NewReader(raw[headerLen:]), 12); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	w := kafkaproto.NewWriter()
	w.WriteRaw(raw[:headerLen])
	if err := resp.Encode(w, 12); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !bytes.Equal(w.Bytes(), raw) {
		t.Fatalf("roundtrip mismatch\nwant: %v\n got: %v", raw, w.Bytes())
	}
}
