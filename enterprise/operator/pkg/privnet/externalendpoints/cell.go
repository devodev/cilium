// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package externalendpoints

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/externalendpoints/providers"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

// Cell provides the automatic creation of external endpoints. It reads
// per-provider configuration files from a config directory and reconciles
// the resulting endpoints into the private networks external endpoints table.
var Cell = cell.Module(
	"privnet-external-endpoints",
	"Private networks external endpoint creation",

	cell.Provide(
		providers.NewSecretsManager,
		providers.NewRegistry,
	),

	cell.Invoke(startInstanceManager),
)

type instanceManagerParams struct {
	cell.In

	Config config.Config

	Registry  *providers.Registry
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	JobGroup  job.Group

	DB    *statedb.DB
	Table statedb.RWTable[*tables.ExternalEndpoint]
}

func startInstanceManager(p instanceManagerParams) error {
	if !p.Config.EnabledWithAutoExternalEndpoints() {
		return nil
	}

	txn := p.DB.WriteTxn(p.Table)
	providerInitializer := p.Table.RegisterInitializer(txn, "providers-synced")
	txn.Commit()

	p.Lifecycle.Append(&instanceManager{
		params: p,
		pendingProviders: &pendingProviders{
			providerInitializer: providerInitializer,
			pending:             make(sets.Set[providers.Name]),
		},
	})

	return nil
}

// pendingProviders keeps track of which providers have not yet emitted a sync event, thereby
// preventing the initializer from being triggered (which in turn will prune any stale endpoints)
type pendingProviders struct {
	mu                  lock.Mutex
	providerInitializer func(statedb.WriteTxn)
	pending             sets.Set[providers.Name]
}

func (p *pendingProviders) Pending(provider providers.Name) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending.Insert(provider)
}

func (p *pendingProviders) Synced(txn statedb.WriteTxn, provider providers.Name) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pending.Delete(provider)
	if len(p.pending) == 0 && p.providerInitializer != nil {
		p.providerInitializer(txn)
		p.pending = nil // gc
		p.providerInitializer = nil
	}
}

type instanceManager struct {
	params           instanceManagerParams
	instances        map[providers.Name]providers.Instance
	pendingProviders *pendingProviders
}

func (c *instanceManager) instanceFromConfigFile(ctx context.Context, configDir fs.FS, fileName string) (config providers.Config, instance providers.Instance, err error) {
	f, err := configDir.Open(fileName)
	if err != nil {
		return config, instance, err
	}
	defer f.Close()

	c.params.Logger.Info("Reading configuration file", logfields.File, fileName)

	err = yaml.NewDecoder(f).Decode(&config)
	if err != nil {
		return config, instance, fmt.Errorf("reading config %q: %w", fileName, err)
	}

	if config.Type == "" {
		return config, instance, fmt.Errorf(`missing "type" key in file: %s`, fileName)
	}

	if config.Name == "" {
		return config, instance, fmt.Errorf(`missing "name" key in file: %s`, fileName)
	}

	provider, err := c.params.Registry.GetProvider(config.Type)
	if err != nil {
		return config, instance, err
	}

	instance, err = provider.NewInstance(ctx, config)
	if err != nil {
		return config, instance, err
	}

	return config, instance, nil
}

func (c *instanceManager) Start(ctx cell.HookContext) error {
	configRoot, err := os.OpenRoot(c.params.Config.AutoExternalEndpoints.ConfigDir)
	if err != nil {
		return fmt.Errorf("opening config dir: %w", err)
	}
	defer configRoot.Close()

	configDir := configRoot.FS()
	files, err := fs.Glob(configDir, "*.yaml")
	if err != nil {
		return err
	}

	var (
		configErrs error

		configs = make(map[providers.Name]providers.Config, len(files))
	)

	c.instances = make(map[providers.Name]providers.Instance, len(files))

	for _, file := range files {
		config, instance, err := c.instanceFromConfigFile(ctx, configDir, file)
		if err != nil {
			// continue parsing so all errors are reported
			configErrs = errors.Join(configErrs, err)
			continue
		}

		if _, exists := c.instances[config.Name]; exists {
			configErrs = errors.Join(configErrs, fmt.Errorf("duplicate instance name: %s", config.Name))
			continue
		}

		c.pendingProviders.Pending(config.Name)
		c.instances[config.Name] = instance

		configs[config.Name] = config
	}

	if configErrs != nil {
		return configErrs
	}

	if len(c.instances) == 0 {
		txn := c.params.DB.WriteTxn(c.params.Table)
		c.pendingProviders.Synced(txn, "")
		txn.Commit()
		return nil
	}

	for name, inst := range c.instances {
		config := configs[name]
		jobName := shortener.ShortenHiveJobName(fmt.Sprintf("%s:%s", config.Type, config.Name))
		changes, err := inst.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start instance %q: %w", config.Name, err)
		}

		h := &instanceHandler{
			providerType: config.Type,
			instanceName: config.Name,
			logger: c.params.Logger.With(
				logfields.ProviderID, config.Type,
				logfields.InstanceID, config.Name,
			),
			db:      c.params.DB,
			table:   c.params.Table,
			pending: c.pendingProviders,
		}

		c.params.JobGroup.Add(
			job.Observer(jobName, h.handleChangeEventBatch, changes),
		)
	}

	return nil
}

func (c *instanceManager) Stop(ctx cell.HookContext) error {
	for _, inst := range c.instances {
		inst.Stop(ctx)
	}
	return nil
}
