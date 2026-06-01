module.exports = {
  repositories: ["isovalent/cilium"],
  username: "isovalent-renovate[bot]",
  prConcurrentLimit: 0,
  prHourlyLimit: 0,
  secrets: {
    RH_REGISTRY_USERNAME: "{{ process.env.RH_REGISTRY_USERNAME }}",
    RH_REGISTRY_PASSWORD: "{{ process.env.RH_REGISTRY_PASSWORD }}",
    ARTIFACTORY_USERNAME: "{{ process.env.ARTIFACTORY_USERNAME }}",
    ARTIFACTORY_PASSWORD: "{{ process.env.ARTIFACTORY_PASSWORD }}",
  },
  hostRules: [
    {
      matchHost: "https://registry.redhat.io",
      hostType: "docker",
      username: "{{ process.env.RH_REGISTRY_USERNAME }}",
      password: "{{ process.env.RH_REGISTRY_PASSWORD }}",
    },
    {
      matchHost: "https://artifactory.devhub-cloud.cisco.com",
      hostType: "docker",
      username: "{{ process.env.ARTIFACTORY_USERNAME }}",
      password: "{{ process.env.ARTIFACTORY_PASSWORD }}",
    },
  ],
  allowedCommands: [
    '^make .*$',
  ],
  customEnvVariables: {
    GOPRIVATE: "github.com/isovalent/*",
  },
  customManagers: [
    {
      customType: 'regex',
      managerFilePatterns: ['/^enterprise/images/wolfi/runtime-base/image\\.yaml$/'],
      matchStrings: [
        '-\\s*(?<packageName>[a-zA-Z0-9_.+-]+)=(?<currentValue>[a-zA-Z0-9_.+-]+)'
      ],
      datasourceTemplate: 'custom.wolfi',
      depNameTemplate: '{{packageName}}',
      versioningTemplate: 'loose'
    }
  ],
  packageRules: [
    {
      matchDatasources: ['custom.wolfi'],
      groupName: 'Wolfi packages',
    },
    {
      matchDatasources: ['custom.wolfi'],
      matchPackageNames: ['iptables', 'ip6tables'],
      enabled: false
    },
    {
      matchPackagePatterns: ['helm.sh/helm/*'],
      enabled: false
    }
  ],
  customDatasources: {
    wolfi: {
      defaultRegistryUrlTemplate: 'http://localhost:8000/{{packageName}}.json',
      transformTemplates: [
        '{"releases": $map($, function($v) { { "version": $v } })}'
      ]
    }
  },
};
