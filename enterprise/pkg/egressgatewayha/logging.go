//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import "log/slog"

const (
	// logfieldReconcileTraceID is key used for top-level scoped logger
	// unique reconcile UUID used as the parent logger for all Operator
	// groupStatus reconcile logging.
	// This allows correlating actions taken within the reconciliation.
	logfieldReconcileTraceID = "reconcileID"

	// logfieldPolicyHealthyGatewayNodes is key used to log the *policy*
	// wide gateway IPs set which is the input for all further policy
	// gateway selection.
	// This plus the state of IEGP configuration is sufficient to determine
	// all selection decisions.
	logfieldPolicyHealthyGatewayNodes = "policyHealthyGatewayNodes"

	// logfieldGroupIndex is key used to create scoped loggers per each
	// group config and status.
	logfieldGroupIndex = "groupIndex"

	// logfieldStatusActiveGatewayIPsByAZ is key used to emit per AZ active
	// gateway IPs from an existing IEGP groupStatus (i.e. the
	// activeGatewaysIPByAZ field).
	logfieldStatusActiveGatewayIPsByAZ = "statusActiveGatewayIPsByAZ"

	// logfieldStatusActiveGatewayIPs is key used to emit active gateway IPs
	// from an existing IEGP groupStatus (i.e. the activeGatewaysIP field).
	logfieldStatusActiveGatewayIPs = "statusActiveGatewayIPs"

	// logfieldStatusNotAvailable is key used for set of gatewayIPs
	// that were used in previous policy status active set but are
	// no longer available for selection (either the node is not
	// available or less likely that the node has changed topology
	// zones).
	logfieldStatusNotAvailable = "statusNotAvailable"

	// logfieldsGatewaySelectionKey is key used for seeding deterministic
	// active gateway selection.
	logfieldGatewaySelectionKey = "gatewaySelectionKey"

	// logfieldSelectionType key is used to add a log field hint passed to
	// doSelection to provide context on *why* this selection is happening.
	// Values will be:
	// * primary: non az affinity selection (i.e. activeGatewayIPs).
	// * azAffinityPrimary: az affinity primary selection into desired local zone.
	// * azAffinityBackfill: az affinity selection fallback in case affinity mode
	//	requires attempting to backfill gateways from non-local zones.
	logfieldSelectionType = "gatewaySelectionType"

	logfieldPolicyUnreachableGatewayIPs = "policyUnreachableGatewayIPs"

	logfieldAffinityMode = "azAffinityMode"

	logfieldsNeededGateways = "neededGateways"

	logfieldsAdvertisedEgressIPs = "AdvertisedEgressIPs"

	// loggingGatewayNodeBatchSize is the max number of the pipeline input nodes
	// we will log per line in logPolicyHealthyGatewayIPs.
	// We use this to break up batches of gateway node IP data into separate log
	// lines to avoid excessive line length.
	loggingGatewayNodeBatchSize = 30
)

func logPolicyHealthyGatewayIPs(logger *slog.Logger, gateways []gatewayNodeIP) {
	for i := 0; i < len(gateways); i += loggingGatewayNodeBatchSize {
		end := min(i+loggingGatewayNodeBatchSize, len(gateways))
		batch := gateways[i:end]
		strs := make([]string, len(batch))
		for j, gn := range batch {
			strs[j] = gn.toStringCompact()
		}
		logger.Info("computed policyHealthyGateways",
			logfieldPolicyHealthyGatewayNodes, strs)
	}
}
