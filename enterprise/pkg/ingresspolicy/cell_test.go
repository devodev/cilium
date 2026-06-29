//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
)

// mockTable replaces the table initialization watch with one controlled by the test.
type mockTable struct {
	statedb.Table[*ciliumenvoyconfig.CEC]
	initWatch chan struct{}
}

func (t *mockTable) Initialized(txn statedb.ReadTxn) (bool, <-chan struct{}) {
	initialized, watch := t.Table.Initialized(txn)
	if !initialized {
		watch = t.initWatch
	}
	return initialized, watch
}

func TestCECReconcilerWakesOnTableInitialization(t *testing.T) {
	t.Parallel()

	db := statedb.New()
	cecs, err := ciliumenvoyconfig.NewCECTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(cecs)
	initialized := cecs.RegisterInitializer(wtxn, "test")
	wtxn.Commit()

	initDone := make(chan struct{})
	mockCECs := &mockTable{
		Table:     cecs,
		initWatch: make(chan struct{}),
	}
	reconciler := &cecReconciler{
		logger:   hivetest.Logger(t),
		db:       db,
		cecs:     mockCECs,
		initDone: initDone,
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(context.Background(), deadline.Add(-time.Second))
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- reconciler.process(ctx, nil)
	}()

	// An unbuffered send completes only when the reconciler waits on the
	// initialization watch returned by Initialized().
	watchSelected := make(chan struct{})
	go func() {
		select {
		case mockCECs.initWatch <- struct{}{}:
			close(watchSelected)
		case <-ctx.Done():
		}
	}()

	select {
	case <-watchSelected:
	case <-ctx.Done():
		cancel()
		require.NoError(t, <-errCh)
		t.Fatal("reconciler did not wait on the table initialization watch")
	}

	// Initialize the empty table without making an object change.
	wtxn = db.WriteTxn(cecs)
	initialized(wtxn)
	wtxn.Commit()

	// Wake any subsequent iteration that captured the controlled watch before
	// the initialization transaction committed.
	close(mockCECs.initWatch)

	// Make sure the table becomes initialized.
	select {
	case <-initDone:
	case <-ctx.Done():
		cancel()
		require.NoError(t, <-errCh)
		t.Fatal("reconciler did not observe table initialization")
	}

	cancel()
	require.NoError(t, <-errCh)
}
