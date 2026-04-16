// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/exec"

	"github.com/cilium/cilium/pkg/backoff"
)

// Like ExecInPodWithWriters, but going through qemu guest agent.
func (c *EnterpriseClient) ExecInVMWithWriters(connCtx context.Context, pod *corev1.Pod, command []string, stdout, stderr io.Writer) error {
	op := qemuAgentCmd{
		Exec: "guest-exec",
		Args: guestExecArgs{
			Path:          command[0],
			Args:          command[1:],
			CaptureOutput: true,
		},
	}

	container := "compute"
	domain := fmt.Sprintf("%s_%s", pod.Namespace, pod.Annotations["kubevirt.io/domain"])

	cmd, err := qemuCommandSlice(domain, op)
	if err != nil {
		return err
	}
	stdoutBuf, err := c.ExecInPod(connCtx, pod.Namespace, pod.Name, container, cmd)
	if err != nil {
		return err
	}

	response, err := extractResponse[guestExecResponse](&stdoutBuf)
	if err != nil {
		return fmt.Errorf("failed to extact PID: %w", err)
	}

	statusCmd := qemuAgentCmd{
		Exec: "guest-exec-status",
		Args: guestExecResponse{
			PID: response.PID,
		},
	}

	bo := backoff.Exponential{
		Max: time.Second * 5,
		Min: time.Millisecond * 200,
	}

	for try := 0; ; try++ {
		select {
		case <-connCtx.Done():
			return connCtx.Err()
		case <-time.After(bo.Duration(try)):
		}

		cmd, err := qemuCommandSlice(domain, statusCmd)
		if err != nil {
			return err
		}
		out, err := c.ExecInPod(connCtx, pod.Namespace, pod.Name, container, cmd)
		if err != nil {
			return err
		}

		status, err := extractResponse[guestExecStatusResponse](&out)
		if err != nil {
			return err
		}
		if status.Exited {
			if _, err := stdout.Write(status.OutData); err != nil {
				return err
			}
			if status.TruncatedOut {
				return errors.New("incomplete stdout")
			}
			if _, err := stderr.Write(status.ErrData); err != nil {
				return err
			}
			if status.TruncatedErr {
				return errors.New("incomplete stderr")
			}
			if status.ExitCode != 0 {
				return exec.CodeExitError{
					Err:  fmt.Errorf("exit code: %d", status.ExitCode),
					Code: status.ExitCode,
				}
			}
			// TODO not sure how to interpret the qemu exec status response docs here.
			if status.Signal != 0 {
				return exec.CodeExitError{
					Err:  fmt.Errorf("signal exit code: %d", status.Signal),
					Code: status.Signal,
				}
			}
			return nil
		}
	}
}

func (c *EnterpriseClient) FindLauncherPodForVM(ctx context.Context, namespace, vm string) (*corev1.Pod, error) {
	pods, err := c.ListPods(ctx, namespace, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("kubevirt.io, vm.kubevirt.io/name=%s", vm),
	})
	if err != nil {
		return nil, err
	}
	if pods == nil || len(pods.Items) == 0 {
		return nil, fmt.Errorf("no virt-launcher pod found for VM %s", vm)
	}
	if n := len(pods.Items); n != 1 {
		return nil, fmt.Errorf("too many virt-launcher pods found for VM %s; got %d, want 1", vm, n)
	}
	return &pods.Items[0], nil
}

func extractResponse[T any](buf *bytes.Buffer) (out T, err error) {
	var response qemuAgentResponse[T]
	if err := json.Unmarshal(buf.Bytes(), &response); err != nil {
		return out, fmt.Errorf("failed to parse exec response: %w", err)
	}
	return response.Return, nil
}

func qemuCommandSlice(domain string, op qemuAgentCmd) ([]string, error) {
	opBytes, err := json.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("failed to build qemu-agent-command: %w", err)
	}
	return []string{
		"virsh",
		"qemu-agent-command",
		domain,
		string(opBytes),
	}, nil
}

type qemuAgentCmd struct {
	Exec string `json:"execute"`
	Args any    `json:"arguments"`
}

type guestExecArgs struct {
	Path          string   `json:"path"`
	Args          []string `json:"arg,omitempty"`
	Env           []string `json:"env,omitempty"`
	Stdin         string   `json:"input-data,omitempty"`
	CaptureOutput bool     `json:"capture-output,omitempty"`
}

type qemuAgentResponse[T any] struct {
	Return T `json:"return,omitzero"`
}

type guestExecResponse struct {
	PID int `json:"pid"`
}

type guestExecStatusResponse struct {
	Exited       bool      `json:"exited"`
	ExitCode     int       `json:"exitcode,omitempty"`
	Signal       int       `json:"signal,omitempty"`
	OutData      base64Str `json:"out-data,omitempty"`
	TruncatedOut bool      `json:"out-truncated,omitempty"`
	ErrData      base64Str `json:"err-data,omitempty"`
	TruncatedErr bool      `json:"err-truncated,omitempty"`
}

type base64Str []byte

func (s *base64Str) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	*s = decoded
	return nil
}
