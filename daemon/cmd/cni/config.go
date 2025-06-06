// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"text/template"

	"github.com/cilium/hive/cell"
	"github.com/containernetworking/cni/libcni"
	"github.com/fsnotify/fsnotify"
	"github.com/google/renameio/v2"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

var legacyConfFile = "05-cilium.conf"

type cniConfigManager struct {
	config      Config
	debug       bool
	cniConfDir  string // computed from WriteCNIConfigWhenReady
	cniConfFile string // computed from WriteCNIConfigWhenReady

	logger     *slog.Logger
	ctx        context.Context
	doneFunc   context.CancelFunc
	controller *controller.Manager

	// watcher watches for changes in the CNI configuration directory
	watcher *fsnotify.Watcher

	status atomic.Pointer[models.Status]
}

// GetMTU returns the MTU as written in the CNI configuration file.
// This is one way to override the node's MTU.
func (c *cniConfigManager) GetMTU() int {
	conf := c.GetCustomNetConf()
	if conf == nil {
		return 0
	}
	return conf.MTU
}

// GetChainingMode returns the configured chaining mode.
func (c *cniConfigManager) GetChainingMode() string {
	return c.config.CNIChainingMode
}

func (c *cniConfigManager) Status() *models.Status {
	return c.status.Load()
}

// ExternalRoutingEnabled returns true if the chained plugin implements routing
// for Endpoints (Pods).
func (c *cniConfigManager) ExternalRoutingEnabled() bool {
	return c.config.CNIExternalRouting
}

// GetCustomNetConf returns the parsed custom CNI configuration, if provided
// (In other words, the value to --read-cni-conf).
// Otherwise, returns nil.
func (c *cniConfigManager) GetCustomNetConf() *cnitypes.NetConf {
	if c.config.ReadCNIConf == "" {
		return nil
	}

	conf, err := cnitypes.ReadNetConf(c.config.ReadCNIConf)
	if err != nil {
		c.logger.Warn(
			"Failed to parse existing CNI configuration file",
			logfields.Error, err,
			logfields.Path, c.config.ReadCNIConf,
		)
		return nil
	}
	return conf
}

// cniConfigs are the default configurations, per chaining mode
var cniConfigs map[string]string = map[string]string{
	// the default
	"none": `
{
  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    }
  ]
}`,

	"flannel": `
{
  "cniVersion": "0.3.1",
  "name": "flannel",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
         "hairpinMode": true,
         "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    },
    {
       "type": "cilium-cni",
       "chaining-mode": "flannel",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    }
  ]
}
`,
	"portmap": `
{
  "cniVersion": "0.3.1",
  "name": "portmap",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": {{.Debug | js }},
       "log-file": "{{.LogFile | js }}"
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
`,
}

// The CNI plugin config we inject in to the plugins[] array of existing AWS configs
const chainedCNIEntry = `
{
	"type": "cilium-cni",
	"chaining-mode": "{{.ChainingMode | js }}",
	"enable-debug": {{.Debug | js }},
	"log-file": "{{.LogFile | js }}"
}
`

const cniControllerName = "write-cni-file"

var cniControllerGroup = controller.NewGroup("write-cni-file")

// startCNIConfWriter starts the CNI configuration file manager.
//
// This has two responsibilities:
// - remove any existing non-Cilium CNI configuration files
// - write the Cilium configuration file when ready.
//
// This is done once the daemon has started up, to signify to the
// kubelet that we're ready to handle sandbox creation.
// There are numerous conflicting CNI options, exposed in Helm and
// the cilium-config config map.
//
// This consumes the following config map keys (or equivalent arguments):
// - write-cni-conf-when-ready=PATH -- path to write the CNI config. If blank, don't manage CNI config
// - read-cni-conf -- A "source" CNI file to use, rather than generating one
// - cni-chaining-mode=MODE -- The CNI configuration format to use, e.g. aws-cni, flannel.
// - cni-exlusive -- if true, then remove other existing CNI configurations
// - cni-log-file=PATH -- A file for the CNI plugin to use for logging
// - debug -- Whether or not the CNI plugin binary should be verbose
func (c *cniConfigManager) Start(cell.HookContext) error {
	if c.config.WriteCNIConfWhenReady == "" {
		c.status.Store(&models.Status{
			Msg:   "CNI configuration management disabled",
			State: models.StatusStateDisabled,
		})
		return nil
	}

	// Watch the CNI configuration directory, and regenerate CNI config
	// if necessary.
	// Don't watch for changes if cni-exclusive is false. This is to allow
	// rewriting of the Cilium CNI configuration by another plugin (e.g. Istio).
	if c.config.CNIExclusive {
		var err error
		c.watcher, err = fsnotify.NewWatcher()
		if err != nil {
			c.logger.Warn(
				"Failed to create watcher",
				logfields.Error, err,
			)
		} else {
			if err := c.watcher.Add(c.cniConfDir); err != nil {
				c.logger.Warn(
					"Failed to watch CNI configuration directory",
					logfields.Error, err,
					logfields.ConfigPath, c.cniConfDir,
				)
				c.watcher = nil
			}
		}
	}

	// Install the CNI file controller
	c.controller.UpdateController(cniControllerName,
		controller.ControllerParams{
			Group: cniControllerGroup,
			DoFunc: func(ctx context.Context) error {
				err := c.setupCNIConfFile()
				if err != nil {
					c.logger.Info(
						"Failed to write CNI config file (will retry)",
						logfields.Error, err,
					)
				}
				return err
			},
			Context:                c.ctx,
			ErrorRetryBaseDuration: 10 * time.Second,
		},
	)

	go c.watchForDirectoryChanges()

	return nil
}

func (c *cniConfigManager) Stop(cell.HookContext) error {
	c.doneFunc()
	c.controller.RemoveAllAndWait()

	if c.watcher != nil {
		c.watcher.Close()
		c.watcher = nil
	}
	return nil
}

// watchForDirectoryChanges re-triggers the CNI controller if any files are changed
// in the CNI configuration directory.
// This has two uses
// - re-generate chained config if the underlying network config has changed
// - remove any other CNI configs if cni.exclusive is true.
func (c *cniConfigManager) watchForDirectoryChanges() {
	if c.watcher == nil {
		return
	}
	for {
		select {
		case _, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			c.logger.Info(
				"Activity in re-generation CNI configuration",
				logfields.ConfigPath, c.cniConfDir,
			)
			c.controller.TriggerController(cniControllerName)
		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			c.logger.Error(
				"Error while watching CNI configuration directory",
				logfields.Error, err,
			)
		case <-c.ctx.Done():
			return
		}
	}
}

// setupCNIConfFile tries to render and write the CNI configuration file to disk.
// Returns error on failure.
func (c *cniConfigManager) setupCNIConfFile() (err error) {
	var contents []byte
	dest := path.Join(c.cniConfDir, c.cniConfFile)

	defer func() {
		if err != nil {
			c.status.Store(&models.Status{
				Msg:   fmt.Sprintf("failed to write CNI configuration file %s: %v", dest, err),
				State: models.StatusStateFailure,
			})
		} else {
			c.status.Store(&models.Status{
				Msg:   fmt.Sprintf("successfully wrote CNI configuration file to %s", dest),
				State: models.StatusStateOk,
			})
		}
	}()

	// generate CNI config, either by reading a user-supplied
	// template file or rendering our own.
	if c.config.ReadCNIConf != "" {
		contents, err = os.ReadFile(c.config.ReadCNIConf)
		if err != nil {
			return fmt.Errorf("failed to read source CNI config file at %s: %w", c.config.ReadCNIConf, err)
		}
		c.logger.Info(
			"Reading CNI configuration file source",
			logfields.ConfigPath, c.config.ReadCNIConf,
		)
	} else {
		contents, err = c.renderCNIConf()
		if err != nil {
			return fmt.Errorf("failed to render CNI configuration file: %w", err)
		}
	}

	err = ensureDirExists(c.cniConfDir)
	if err != nil {
		return fmt.Errorf("failed to create the dir %s of the CNI configuration file: %w", c.cniConfDir, err)
	}

	// Check to see if existing file is the same; if so, do nothing
	existingContents, err := os.ReadFile(dest)
	if err == nil && bytes.Equal(existingContents, contents) {
		c.logger.Debug(
			"Existing CNI configuration file unchanged",
			logfields.Destination, dest,
		)
	} else {
		if err != nil && !os.IsNotExist(err) {
			c.logger.Debug(
				"Failed to read existing CNI configuration file",
				logfields.Error, err,
				logfields.Destination, dest,
			)
		}
		// commit CNI config
		if err := renameio.WriteFile(dest, contents, 0600); err != nil {
			return fmt.Errorf("failed to write CNI configuration file at %s: %w", dest, err)
		}
		c.logger.Info(
			"Wrote CNI configuration file",
			logfields.Error, err,
			logfields.Destination, dest,
		)
	}

	// Rename away any non-cilium CNI config files.
	c.cleanupOtherCNI()

	return nil
}

// renderCNIConf renders the CNI configuration file based on the parameters.
// It may generate a configuration file from scratch or inject Cilium
// in to an existing CNI network.
func (c *cniConfigManager) renderCNIConf() (cniConfig []byte, err error) {
	if c.config.CNIChainingTarget != "" {
		pluginConfig := c.renderCNITemplate(chainedCNIEntry)
		cniConfig, err = c.mergeExistingCNIConfig(pluginConfig)
		if err != nil {
			return nil, err
		}
	} else {
		c.logger.Info(
			"Generating CNI configuration file with mode",
			logfields.Mode, c.config.CNIChainingMode,
		)
		tmpl := cniConfigs[strings.ToLower(c.config.CNIChainingMode)]
		cniConfig = []byte(c.renderCNITemplate(tmpl))
	}

	if len(cniConfig) == 0 {
		return nil, fmt.Errorf("invalid CNI chaining mode: %s", c.config.CNIChainingMode)
	}

	return cniConfig, nil
}

// mergeExistingCNIConfig looks for an existing cni configuration
// and modifies it to include Cilium. If no configuration is found, it
// fails.
//
// pluginConfig is the raw json to insert in the plugin chain.
//
// This was originally added to interact solely with aws-cni, see
// PR #18522 for details.
func (c *cniConfigManager) mergeExistingCNIConfig(pluginConfig []byte) ([]byte, error) {
	contents, err := c.findCNINetwork(c.config.CNIChainingTarget)
	if err != nil {
		return nil, fmt.Errorf("could not find existing CNI config for chaining: %w", err)
	}

	// Check to see if we're already inserted; otherwise we should append
	index := int64(-1)
	res := gjson.GetBytes(contents, `plugins.#.type`)
	res.ForEach(func(key gjson.Result, value gjson.Result) bool {
		if value.String() == "cilium-cni" {
			index = key.Int()
			return false
		}
		return true
	})

	// Inject cilium in to the plugins[] array, appending or overwriting if it
	// already existed.
	out, err := sjson.SetRawBytes(contents, fmt.Sprintf("plugins.%d", index), pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to modify existing CNI config: %w", err)
	}
	c.logger.Info(
		"Generated chained cilium CNI configuration",
		logfields.Target, c.config.CNIChainingTarget,
	)
	return out, nil
}

// renderCNITemplate applies any cni template replacements
// currently: Debug, LogFile, and ChainingMode
func (c *cniConfigManager) renderCNITemplate(in string) []byte {
	data := struct {
		Debug        bool
		LogFile      string
		ChainingMode string
	}{
		Debug:        c.debug,
		LogFile:      c.config.CNILogFile,
		ChainingMode: c.config.CNIChainingMode,
	}

	t := template.Must(template.New("cni").Parse(in))

	out := bytes.Buffer{}
	if err := t.Execute(&out, data); err != nil {
		panic(err) // impossible
	}
	return out.Bytes()
}

// cleanupOtherCNI renames any existing CNI configuration files with the suffix
// ".cilium_bak", excepting files in keep
func (c *cniConfigManager) cleanupOtherCNI() error {
	// remove the old 05-cilium.conf, now that we write 05-cilium.conflist
	if c.cniConfFile != legacyConfFile {
		_ = os.Rename(path.Join(c.cniConfDir, legacyConfFile), path.Join(c.cniConfDir, legacyConfFile+".cilium_bak"))
	}

	if !c.config.CNIExclusive {
		return nil
	}
	files, err := os.ReadDir(c.cniConfDir)
	if err != nil {
		return fmt.Errorf("failed to list CNI conf dir %s: %w", c.cniConfDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if name == c.cniConfFile {
			continue
		}
		if !(strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".conflist") || strings.HasSuffix(name, ".json")) {
			continue
		}

		c.logger.Info(
			"Renaming non-Cilium CNI configuration file",
			logfields.Source, name,
			logfields.Destination, name+".cilium_bak",
		)
		_ = os.Rename(path.Join(c.cniConfDir, name), path.Join(c.cniConfDir, name+".cilium_bak"))
	}
	return nil
}

// findCNINetwork scans a given directory for CNI configuration files,
// returning the path to a file that contains a CNI **network** with the name
// supplied.
func (c *cniConfigManager) findCNINetwork(wantNetwork string) ([]byte, error) {
	files, err := libcni.ConfFiles(c.cniConfDir, []string{".conflist", ".conf", ".json", ".cilium_bak"})
	if err != nil {
		return nil, fmt.Errorf("failed to list files in %s: %w", c.cniConfDir, err)
	}
	slices.Sort(files)

	for _, file := range files {
		// Don't inject ourselves in to ourselves :-)
		if _, filename := path.Split(file); filename == c.cniConfFile {
			continue
		}
		contents, err := os.ReadFile(file)
		if err != nil {
			c.logger.Warn(
				"Could not read CNI configuration file, skipping.",
				logfields.Error, err,
				logfields.Path, file,
			)
			continue
		}

		rawConfig := make(map[string]any)
		if err := json.Unmarshal(contents, &rawConfig); err != nil {
			c.logger.Warn(
				"CNI configuration file has invalid json, skipping.",
				logfields.Error, err,
				logfields.Path, file,
			)
			continue
		}

		netName, ok := rawConfig["name"].(string)
		if !ok {
			continue
		}

		// "*" indicates select the first valid file. It is not a valid CNI network name
		if wantNetwork != "*" && wantNetwork != netName {
			continue
		}

		c.logger.Info(
			"Found CNI network for chaining",
			logfields.Name, netName,
			logfields.Path, file,
		)

		// Check to see if we need to upconvert to a CNI configuration list.
		// The presence of a "plugins" configuration key means this is a conflist
		plugins, ok := rawConfig["plugins"].([]any)
		if ok && len(plugins) > 0 {
			return contents, nil
		}

		rawConfigList := map[string]any{
			"name":       wantNetwork,
			"cniVersion": rawConfig["cniVersion"],
			"plugins":    []any{rawConfig},
		}

		return json.Marshal(rawConfigList)
	}
	return nil, fmt.Errorf("no matching CNI configurations found (will retry)")
}

func ensureDirExists(dir string) error {
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil && os.IsExist(err) {
		return nil
	}
	return err
}
