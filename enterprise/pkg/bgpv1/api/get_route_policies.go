// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package api

import (
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/api"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
)

func NewGetRoutePoliciesHandler(c *agent.Controller) restapi.GetBgpRoutePoliciesHandler {
	return &getRoutePoliciesHandler{
		controller: c,
	}
}

type getRoutePoliciesHandler struct {
	controller *agent.Controller
}

func (h *getRoutePoliciesHandler) Handle(params restapi.GetBgpRoutePoliciesParams) middleware.Responder {
	if h.controller == nil {
		return api.Error(http.StatusNotImplemented, ossAgent.ErrBGPControlPlaneDisabled)
	}

	policies, err := h.controller.BGPMgr.GetRoutePoliciesLegacy(params.HTTPRequest.Context(), params)
	if err != nil {
		return api.Error(http.StatusInternalServerError, fmt.Errorf("failed to get route policies: %w", err))
	}
	return restapi.NewGetBgpRoutePoliciesOK().WithPayload(policies)
}
