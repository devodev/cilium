//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/time"
)

const xdsSnapshotTableName = "xds-snapshots"

type XDSSnapshotState struct {
	SnapshotKey string
	Version     string
	// Keep counts as separate fields so inspection can show a compact summary
	// without reparsing the serialized xDS resource payloads.
	NumListeners int
	NumRoutes    int
	NumClusters  int
	NumEndpoints int
	NumSecrets   int
	Listeners    string
	Routes       string
	Clusters     string
	Endpoints    string
	Secrets      string
	UpdatedAt    time.Time
}

var xdsSnapshotIndex = statedb.Index[*XDSSnapshotState, string]{
	Name: "snapshot-key",
	FromObject: func(obj *XDSSnapshotState) index.KeySet {
		return index.NewKeySet(index.String(obj.SnapshotKey))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

func newXDSSnapshotStateTable(db *statedb.DB) (statedb.RWTable[*XDSSnapshotState], error) {
	return statedb.NewTable(
		db,
		xdsSnapshotTableName,
		xdsSnapshotIndex,
	)
}

func (s *XDSSnapshotState) Clone() *XDSSnapshotState {
	clone := *s
	return &clone
}

func (s *XDSSnapshotState) TableHeader() []string {
	return []string{"SnapshotKey", "Version", "Listeners", "Routes", "Clusters", "Endpoints", "Secrets", "UpdatedAt"}
}

func (s *XDSSnapshotState) TableRow() []string {
	return []string{
		s.SnapshotKey,
		s.Version,
		strconv.Itoa(s.NumListeners),
		strconv.Itoa(s.NumRoutes),
		strconv.Itoa(s.NumClusters),
		strconv.Itoa(s.NumEndpoints),
		strconv.Itoa(s.NumSecrets),
		s.UpdatedAt.Format(time.RFC3339),
	}
}

func newXDSSnapshotState(snapshotKey string, version string, resources XDSResources) (*XDSSnapshotState, error) {
	listeners, err := marshalProtoSlice(resources.Listeners)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal listeners: %w", err)
	}

	routes, err := marshalProtoSlice(resources.Routes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal routes: %w", err)
	}

	clusters, err := marshalProtoSlice(resources.Clusters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal clusters: %w", err)
	}

	endpoints, err := marshalProtoSlice(resources.Endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal endpoints: %w", err)
	}

	secrets, err := marshalProtoSlice(resources.Secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secrets: %w", err)
	}

	return &XDSSnapshotState{
		SnapshotKey:  snapshotKey,
		Version:      version,
		NumListeners: len(resources.Listeners),
		NumRoutes:    len(resources.Routes),
		NumClusters:  len(resources.Clusters),
		NumEndpoints: len(resources.Endpoints),
		NumSecrets:   len(resources.Secrets),
		Listeners:    listeners,
		Routes:       routes,
		Clusters:     clusters,
		Endpoints:    endpoints,
		Secrets:      secrets,
		UpdatedAt:    time.Now(),
	}, nil
}

func marshalProtoSlice[T proto.Message](items []T) (string, error) {
	if len(items) == 0 {
		return "[]", nil
	}

	marshaled := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		data, err := protojson.MarshalOptions{
			Indent:        "  ",
			UseProtoNames: true,
		}.Marshal(item)
		if err != nil {
			return "", err
		}
		marshaled = append(marshaled, data)
	}

	data, err := json.MarshalIndent(marshaled, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
