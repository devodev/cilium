//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sysdump

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/pkg/versioncheck"
)

var (
	timescapeBugtoolCommand = []string{"/usr/bin/hubble-timescape", "bugtool", "--out", "-"}
	timescapeVersionCommand = []string{"/usr/bin/hubble-timescape", "version"}

	timescapeUIBugtoolCommand = []string{"/usr/bin/hubble-timescape-ui", "bugtool", "--out", "-"}
)

// SubmitTimescapeBugtoolTasks takes a list of timescape pods and will submit tasks to collect bugtool output for them
func SubmitTimescapeBugtoolTasks(c *sysdump.Collector, pods []*corev1.Pod, timescapeBugtoolPrefix string, bugtoolFlags []string) error {
	var submitErrors []error
	for _, p := range pods {
		switch component := p.GetLabels()["app.kubernetes.io/component"]; component {
		case "server", "analyzer":
			err := submitTimescapeBugtoolTaskForContainer(c, p, component, timescapeBugtoolTaskConfig{
				prefix:           timescapeBugtoolPrefix,
				bugtoolExtraArgs: bugtoolFlags,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "ingester":
			user, pwRef, err := extractMigrateCredentials(p)
			if err != nil {
				submitErrors = append(submitErrors, fmt.Errorf("failed to extract privileged ClickHouse credentials from the Timescape Pod, continuing with unprivileged user: %w", err))
			}
			err = submitTimescapeBugtoolTaskForContainer(c, p, "ingester", timescapeBugtoolTaskConfig{
				prefix:                timescapeBugtoolPrefix,
				bugtoolExtraArgs:      bugtoolFlags,
				collectClickhouse:     true,
				clickhouseUsername:    user,
				clickhousePwSecretRef: pwRef,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "lite", "hubble-timescape":
			err := submitTimescapeBugtoolTaskForContainer(c, p, "timescape", timescapeBugtoolTaskConfig{
				prefix:            timescapeBugtoolPrefix,
				bugtoolExtraArgs:  bugtoolFlags,
				collectClickhouse: true,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "ui":
			err := submitTimescapeUIBugtoolTaskForContainer(c, p, "ui", timescapeUIBugtoolTaskConfig{
				prefix:           timescapeBugtoolPrefix,
				bugtoolExtraArgs: bugtoolFlags,
			})
			if err != nil {
				submitErrors = append(submitErrors, err)
			}
		case "trimmer", "database":
			// The trimmer is a job and can't give us bugtool output
			// The database pod is ClickHouse, we can't get bugtool output either
		default:
			// Unknown component
			submitErrors = append(submitErrors, fmt.Errorf("unexpected timescape pod %s/%s (component:%s), skipping", p.GetNamespace(), p.GetName(), component))
		}
	}
	return errors.Join(submitErrors...)
}

type timescapeBugtoolTaskConfig struct {
	prefix string

	bugtoolExtraArgs []string

	collectClickhouse     bool
	clickhouseUsername    string
	clickhousePwSecretRef *corev1.SecretKeySelector
}

type bugToolFunc func(ctx context.Context) (stdout io.Reader, stderr io.Reader, err error)

func submitBugtoolTaskForContainer(c *sysdump.Collector, p *corev1.Pod, containerName string, prefix string, runBugtool bugToolFunc) error {
	workerID := fmt.Sprintf("%s-%s-%s-%s", prefix, p.Namespace, p.Name, containerName)
	if err := c.Pool.Submit(workerID, func(ctx context.Context) error {
		var errs error

		stdout, stderr, err := runBugtool(ctx)
		if err != nil {
			// Even if the bugtool run failed, there might be valid partial output,
			// let's still try to capture it
			errs = errors.Join(errs, err)
		}

		if err := c.WithFileSink(fmt.Sprintf("%s-<ts>.log", workerID), func(bugtoolLogFile io.Writer) error {
			_, err := io.Copy(bugtoolLogFile, stderr)
			return err
		}); err != nil {
			errs = errors.Join(errs, err)
		}

		// Extract content
		dir := c.AbsoluteTempPath(fmt.Sprintf("%s-<ts>", workerID))
		if err := untarTo(stdout, dir); err != nil {
			errs = errors.Join(errs, err)
		}

		if errs != nil {
			return fmt.Errorf("failure collecting 'timescape-bugtool' output for %q in namespace %q, the output might be missing or incomplete:\n %w", p.Name, p.Namespace, errs)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to submit 'timescape-bugtool' task for %q: %w", p.Name, err)
	}
	return nil
}

func submitTimescapeBugtoolTaskForContainer(c *sysdump.Collector, p *corev1.Pod, containerName string, cfg timescapeBugtoolTaskConfig) error {
	return submitBugtoolTaskForContainer(c, p, containerName, cfg.prefix, func(ctx context.Context) (io.Reader, io.Reader, error) {
		return runTimescapeBugtool(ctx, c.Client, p.Namespace, p.Name, containerName, cfg)
	})
}

func submitTimescapeUIBugtoolTaskForContainer(c *sysdump.Collector, p *corev1.Pod, containerName string, cfg timescapeUIBugtoolTaskConfig) error {
	return submitBugtoolTaskForContainer(c, p, containerName, cfg.prefix, func(ctx context.Context) (io.Reader, io.Reader, error) {
		return runTimescapeUIBugtool(ctx, c.Client, p.Namespace, p.Name, containerName, cfg)
	})
}

type timescapeBugtoolKubernetesClient interface {
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
}

func runTimescapeBugtool(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, name string, containerName string, cfg timescapeBugtoolTaskConfig) (io.Reader, io.Reader, error) {
	var errs error
	command := timescapeBugtoolCommand
	if cfg.collectClickhouse {
		// Only available since v1.5.0
		// Check timescape version to decide what flags are valid
		v, err := getTimescapeVersion(ctx, c, namespace, name, containerName)
		if err != nil {
			// If there is an error collect it and treat it as the most recent version
			errs = errors.Join(errs, fmt.Errorf("failed to get timescape version, continuing with most recent version: %w", err))
		}
		if v == nil || versioncheck.MustCompile(">=1.5.0")(*v) {
			command = append(command, "--collect-clickhouse-stats")
			if cfg.clickhouseUsername != "" && cfg.clickhousePwSecretRef != nil {
				pw, err := getSecretKey(ctx, c, namespace, cfg.clickhousePwSecretRef)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to get timescape clickhouse credentials, continuing with local credentials: %w", err))
				} else {
					command = append(command, fmt.Sprintf("--clickhouse-username=%s", cfg.clickhouseUsername), fmt.Sprintf("--clickhouse-password=%s", pw))
				}
			}
		}
	}

	command = append(command, cfg.bugtoolExtraArgs...)
	// Run 'hubble-timescape bugtool' in the pod and collect stdout
	stdout, stderr, err := c.ExecInPodWithStderr(ctx, namespace, name, containerName, command)
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed run 'timescape bugtool': %w:\n%s", err, stderr.String()))
	}
	return &stdout, &stderr, errs
}

func getTimescapeVersion(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, name string, containerName string) (*semver.Version, error) {
	o, _, err := c.ExecInPodWithStderr(
		ctx,
		namespace,
		name,
		containerName,
		timescapeVersionCommand,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch timescape version of pod %q: %w", name, err)
	}

	// The version string is of the form
	// hubble-timescape 1.x.x compiled with go1.xx.x on linux/amd64
	// Take the second field and try to parse it
	fields := strings.Fields(strings.TrimSpace(o.String()))
	if len(fields) < 2 {
		return nil, fmt.Errorf("unable to parse timescape version %s of pod %s: %w", o.String(), name, err)
	}
	v, _, _ := strings.Cut(strings.TrimSpace(fields[1]), "-") // strips proprietary -releaseX suffix
	podVersion, err := semver.ParseTolerant(v)
	if err != nil {
		return nil, fmt.Errorf("unable to parse timescape version %s of pod %s: %w", o.String(), name, err)
	}

	return &podVersion, nil
}

type timescapeUIBugtoolTaskConfig struct {
	prefix string

	bugtoolExtraArgs []string
}

func runTimescapeUIBugtool(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, name string, containerName string, cfg timescapeUIBugtoolTaskConfig) (io.Reader, io.Reader, error) {
	bugtoolCommand := append(timescapeUIBugtoolCommand, cfg.bugtoolExtraArgs...)
	// Run 'hubble-timescape bugtool' in the pod and collect stdout
	stdout, stderr, err := c.ExecInPodWithStderr(ctx, namespace, name, containerName, bugtoolCommand)
	if err != nil {
		// wrap the error, but don't return yet, as we want to return stdout/stderr if there is anything there to return.
		err = fmt.Errorf("failed run 'ui bugtool': %w:\n%s", err, stderr.String())
	}
	return &stdout, &stderr, err
}

func getSecretKey(ctx context.Context, c timescapeBugtoolKubernetesClient, namespace string, secretRef *corev1.SecretKeySelector) (string, error) {
	pwSecret, err := c.GetSecret(ctx, namespace, secretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if pwSecret == nil {
		return "", errors.New("failed to find secret")
	}

	pw, ok := pwSecret.Data[secretRef.Key]
	if !ok {
		return "", errors.New("failed to find key in secret")
	}
	return string(pw), nil
}

func extractMigrateCredentials(ingesterPod *corev1.Pod) (string, *corev1.SecretKeySelector, error) {
	var migrateContainer *corev1.Container
	for _, c := range ingesterPod.Spec.InitContainers {
		if c.Name == "migrate" {
			migrateContainer = &c
		}
	}
	if migrateContainer == nil {
		return "", nil, errors.New("no migrate initContainer found")
	}

	var chUser string
	var chPwSecretRef *corev1.SecretKeySelector
	for _, env := range migrateContainer.Env {
		switch env.Name {
		case "HUBBLE_TIMESCAPE_CLICKHOUSE_USERNAME":
			chUser = env.Value
		case "HUBBLE_TIMESCAPE_CLICKHOUSE_PASSWORD":
			chPwSecretRef = env.ValueFrom.SecretKeyRef
		}
	}
	if chPwSecretRef == nil {
		return "", nil, errors.New("failed to get secret reference from env var `HUBBLE_TIMESCAPE_CLICKHOUSE_PASSWORD`")
	}
	if chUser == "" {
		return "", nil, errors.New("failed to get username form env var `HUBBLE_TIMESCAPE_CLICKHOUSE_USERNAME`")
	}

	return chUser, chPwSecretRef, nil
}

func untarTo(in io.Reader, dst string) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		// Bugtool tar files don't contain headers for
		// directories, so create a directory for each file instead.
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name, err := removeTopDirectory(header.Name)
		if err != nil {
			return nil
		}
		filename := filepath.Join(dst, name)
		directory := filepath.Dir(filename)
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		if err = copyN(f, tr, 1024); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
}

func removeTopDirectory(path string) (string, error) {
	// file separator hardcoded because sysdump always created on Linux OS
	_, after, ok := strings.Cut(path, "/")
	if !ok {
		return "", fmt.Errorf("invalid path %q", path)
	}

	return after, nil
}

// copyN copies from src to dst n bytes at a time to avoid this lint error:
// G110: Potential DoS vulnerability via decompression bomb (gosec)
func copyN(dst io.Writer, src io.Reader, n int64) error {
	for {
		_, err := io.CopyN(dst, src, n)
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
	}
}
