//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	docker_client "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

type Client struct {
	*docker_client.Client
}

type ExitError struct {
	Err  error
	Code int
}

func (e ExitError) Error() string { return e.Err.Error() }
func (e ExitError) ExitCode() int { return e.Code }

func NewClient() (*Client, error) {
	cli, err := docker_client.NewClientWithOpts(
		docker_client.FromEnv,
		docker_client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}

	return &Client{cli}, nil
}

func (c *Client) ContainerExec(ctx context.Context, name string, cmds []string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	execConfig := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmds,
	}

	execID, err := c.ContainerExecCreate(ctx, name, execConfig)
	if err != nil {
		return "", "", err
	}

	resp, err := c.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", "", err
	}
	defer resp.Close()

	_, err = stdcopy.StdCopy(&stdout, &stderr, resp.Reader)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	inspect, err := c.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	if inspect.ExitCode != 0 {
		return stdout.String(), stderr.String(), ExitError{
			Err:  fmt.Errorf("cmd failed: %d", inspect.ExitCode),
			Code: inspect.ExitCode,
		}
	}

	return stdout.String(), stderr.String(), err
}

func (c *Client) ContainerExecDetached(ctx context.Context, name string, cmds []string) (io.Reader, error) {
	execConfig := container.ExecOptions{
		Detach:       true,
		Tty:          true, // prevents cryptic character at line start when copying to stdout
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmds,
	}

	execID, err := c.ContainerExecCreate(ctx, name, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to exec command: %w", err)
	}

	resp, err := c.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{
		Tty: true, // prevents cryptic character at line start when copying to stdout
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return resp.Reader, err
}
