// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package exporter

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	timescapepb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"
)

const ingestBatchMethodName = "IngestBatch"

type ingestCapabilities struct {
	flow bool
}

func reflectIngestCapabilities(ctx context.Context, client grpc.ClientConnInterface) (ingestCapabilities, bool, error) {
	serviceName := timescapepb.IngesterService_ServiceDesc.ServiceName
	stream, err := reflectionpb.NewServerReflectionClient(client).ServerReflectionInfo(ctx)
	if err != nil {
		return ingestCapabilities{}, false, fmt.Errorf("open reflection stream: %w", err)
	}
	defer stream.CloseSend()

	request := &reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	}
	if err := stream.Send(request); err != nil {
		return ingestCapabilities{}, false, fmt.Errorf("request ingester descriptor: %w", err)
	}
	response, err := stream.Recv()
	if err != nil {
		return ingestCapabilities{}, false, fmt.Errorf("receive ingester descriptor: %w", err)
	}

	switch message := response.GetMessageResponse().(type) {
	case *reflectionpb.ServerReflectionResponse_ErrorResponse:
		return ingestCapabilities{}, false, fmt.Errorf(
			"reflect ingester descriptor: code=%d message=%q",
			message.ErrorResponse.GetErrorCode(),
			message.ErrorResponse.GetErrorMessage(),
		)
	case *reflectionpb.ServerReflectionResponse_FileDescriptorResponse:
		return inspectIngestCapabilities(
			message.FileDescriptorResponse.GetFileDescriptorProto(),
			serviceName,
		)
	default:
		return ingestCapabilities{}, false, fmt.Errorf("unexpected reflection response %T", message)
	}
}

func inspectIngestCapabilities(rawDescriptors [][]byte, serviceName string) (ingestCapabilities, bool, error) {
	files := make([]*descriptorpb.FileDescriptorProto, 0, len(rawDescriptors))
	for _, rawDescriptor := range rawDescriptors {
		file := new(descriptorpb.FileDescriptorProto)
		if err := proto.Unmarshal(rawDescriptor, file); err != nil {
			return ingestCapabilities{}, false, fmt.Errorf("unmarshal reflected descriptor: %w", err)
		}
		files = append(files, file)
	}

	var requestType string
	serviceFound := false
	for _, file := range files {
		for _, service := range file.GetService() {
			if fullName(file.GetPackage(), service.GetName()) != serviceName {
				continue
			}
			serviceFound = true
			for _, method := range service.GetMethod() {
				if method.GetName() == ingestBatchMethodName {
					requestType = strings.TrimPrefix(method.GetInputType(), ".")
					break
				}
			}
		}
	}
	if !serviceFound {
		return ingestCapabilities{}, false, fmt.Errorf("reflected descriptors omit service %q", serviceName)
	}
	if requestType == "" {
		return ingestCapabilities{}, false, nil
	}

	for _, file := range files {
		for _, message := range file.GetMessageType() {
			if fullName(file.GetPackage(), message.GetName()) != requestType {
				continue
			}
			return inspectBatchRequest(message), true, nil
		}
	}
	return ingestCapabilities{}, false, fmt.Errorf("reflected descriptors omit request %q", requestType)
}

func inspectBatchRequest(message *descriptorpb.DescriptorProto) ingestCapabilities {
	dataOneof := int32(-1)
	for index, oneof := range message.GetOneofDecl() {
		if oneof.GetName() == "data" {
			dataOneof = int32(index)
			break
		}
	}
	if dataOneof < 0 {
		return ingestCapabilities{}
	}

	capabilities := ingestCapabilities{}
	for _, field := range message.GetField() {
		if field.OneofIndex == nil || field.GetOneofIndex() != dataOneof {
			continue
		}
		switch field.GetName() {
		case "flow_batch":
			capabilities.flow = true
		}
	}
	return capabilities
}

func fullName(packageName, name string) string {
	if packageName == "" {
		return name
	}
	return packageName + "." + name
}
