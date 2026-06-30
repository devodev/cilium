module github.com/cilium/cilium

go 1.26.0

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.22.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8 v8.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9 v9.0.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.63.107
	github.com/aws/aws-sdk-go-v2 v1.42.0
	github.com/aws/aws-sdk-go-v2/config v1.32.25
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.29
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.308.0
	github.com/aws/smithy-go v1.27.2
	github.com/blang/semver/v4 v4.0.0
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cilium/charts v0.0.0-20260616122432-1c427957de0a
	github.com/cilium/coverbee v0.3.3-0.20240723084546-664438750fce
	github.com/cilium/dns v1.1.51-0.20240603182237-af788769786a
	github.com/cilium/ebpf v0.21.0
	github.com/cilium/endpointslice-controller v0.0.0-20250410163339-ffb33e27879c
	github.com/cilium/fake v0.7.0
	github.com/cilium/hive v1.0.4
	github.com/cilium/lumberjack/v2 v2.4.2
	github.com/cilium/proxy v0.0.0-20260508102643-7c2f6580d32e
	github.com/cilium/statedb v0.8.2
	github.com/cilium/stream v0.0.1
	github.com/cilium/workerpool v1.4.0
	github.com/cloudflare/cfssl v1.6.5
	github.com/containernetworking/cni v1.3.0
	github.com/corazawaf/coraza/v3 v3.7.0
	github.com/coreos/go-iptables v0.8.0
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/docker/docker v28.5.2+incompatible
	github.com/envoyproxy/go-control-plane v0.14.0
	github.com/envoyproxy/go-control-plane/envoy v1.37.0
	github.com/evanphx/json-patch/v5 v5.9.11
	github.com/fatih/color v1.19.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/go-logr/logr v1.4.3
	github.com/go-openapi/errors v0.22.8
	github.com/go-openapi/loads v0.24.0
	github.com/go-openapi/runtime v0.32.4
	github.com/go-openapi/spec v0.22.6
	github.com/go-openapi/strfmt v0.26.3
	github.com/go-openapi/swag v0.26.1
	github.com/go-openapi/swag/cmdutils v0.26.1
	github.com/go-openapi/swag/conv v0.26.1
	github.com/go-openapi/swag/jsonutils v0.26.1
	github.com/go-openapi/swag/typeutils v0.26.1
	github.com/go-openapi/validate v0.26.0
	github.com/golang/protobuf v1.5.4
	github.com/google/cel-go v0.28.1
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v88 v88.0.0
	github.com/google/go-licenses/v2 v2.0.1
	github.com/google/gops v0.3.28
	github.com/google/renameio/v2 v2.0.2
	github.com/google/uuid v1.6.0
	github.com/gopacket/gopacket v1.6.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.3
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/hmarr/codeowners v1.2.1
	github.com/jeremywohl/flatten v1.0.1
	github.com/json-iterator/go v1.1.12
	github.com/kevinburke/ssh_config v1.6.0
	github.com/klauspost/compress v1.18.6
	github.com/lthibault/jitterbug/v2 v2.2.2
	github.com/mackerelio/go-osstat v0.2.7
	github.com/mattn/go-shellwords v1.0.13
	github.com/mdlayher/arp v0.0.0-20260528070854-93566ba168e9
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118
	github.com/mdlayher/ndp v1.1.0
	github.com/mdlayher/packet v1.1.2
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/ginkgo/v2 v2.28.1
	github.com/onsi/gomega v1.40.0
	github.com/osrg/gobgp/v4 v4.6.1-0.20260630022313-d6dee8360046
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
	github.com/prometheus-community/pro-bing v0.9.0
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.69.0
	github.com/prometheus/procfs v0.20.1
	github.com/russross/blackfriday/v2 v2.1.0
	github.com/sasha-s/go-deadlock v0.3.9
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/afero v1.15.0
	github.com/spf13/cast v1.10.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
	github.com/spiffe/go-spiffe/v2 v2.8.1
	github.com/spiffe/spire-api-sdk v1.15.1
	github.com/stretchr/testify v1.11.1
	github.com/tidwall/gjson v1.19.0
	github.com/tidwall/sjson v1.2.5
	github.com/vishvananda/netlink v1.3.2-0.20260624190457-bab08b3566fc
	github.com/vishvananda/netns v0.0.5
	github.com/vmware/govmomi v0.53.0
	go.etcd.io/etcd/api/v3 v3.6.12
	go.etcd.io/etcd/client/pkg/v3 v3.6.12
	go.etcd.io/etcd/client/v3 v3.6.12
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.28.0
	go.yaml.in/yaml/v3 v3.0.4
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.53.0
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976
	golang.org/x/mod v0.37.0
	golang.org/x/net v0.56.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.21.0
	golang.org/x/sys v0.46.0
	golang.org/x/term v0.44.0
	golang.org/x/text v0.38.0
	golang.org/x/time v0.15.0
	golang.org/x/tools v0.46.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260622175928-b703f567277d
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
	helm.sh/helm/v4 v4.2.2
	k8s.io/api v0.36.2
	k8s.io/apiextensions-apiserver v0.36.2
	k8s.io/apimachinery v0.36.2
	k8s.io/cli-runtime v0.36.2
	k8s.io/client-go v0.36.2
	k8s.io/component-base v0.36.2
	k8s.io/endpointslice v0.36.2
	k8s.io/klog/v2 v2.140.0
	k8s.io/kubectl v0.36.2
	k8s.io/metrics v0.36.2
	k8s.io/utils v0.0.0-20260617174310-a95e086a2553
	sigs.k8s.io/controller-runtime v0.24.1
	sigs.k8s.io/gateway-api v1.5.1
	sigs.k8s.io/gateway-api/conformance v1.5.1
	sigs.k8s.io/mcs-api v0.5.1-0.20260611073251-db147c3e167e
	sigs.k8s.io/mcs-api/conformance v0.5.1-0.20260611073251-db147c3e167e
	sigs.k8s.io/mcs-api/controllers v0.5.1-0.20260611073251-db147c3e167e
	sigs.k8s.io/network-policy-api v0.2.0
	sigs.k8s.io/yaml v1.6.0
)

// Enterprise specific deps
require (
	github.com/YutaroHayakawa/bgplay v0.0.4
	github.com/YutaroHayakawa/go-ra v0.0.0-20241125075947-1274124821d6
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2
	github.com/coreos/go-oidc/v3 v3.17.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/go-playground/validator/v10 v10.30.1
	github.com/insomniacslk/dhcp v0.0.0-20251020182700-175e84fbb167
	github.com/int128/listener v1.3.0
	github.com/isovalent/hubble-timescape/api v1.19.0
	github.com/isovalent/ipa v1.19.0
	github.com/jonboulle/clockwork v0.5.0
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.7.6
	github.com/lestrrat-go/jwx/v2 v2.1.6
	github.com/mdlayher/socket v0.5.1
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8
	github.com/vmware/go-ipfix v0.16.0
	kubevirt.io/api v1.7.2
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260415201107-50325440f8f2.1 // indirect
	cel.dev/expr v0.25.1 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.7.2 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/alecthomas/participle/v2 v2.1.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/cilium/deepequal-gen v0.0.0-20241016021505-f57df2fe2e62 // indirect
	github.com/cilium/endpointslice v0.29.4-0.20240409195643-982ad68ab7ba // indirect
	github.com/cilium/linters v0.4.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/containerd/errdefs v0.3.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/corazawaf/libinjection-go v0.3.2 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/creasty/defaults v1.7.0 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dylibso/observe-sdk/go v0.0.0-20240819160327-2d926c5d788a // indirect
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/envoyproxy/go-control-plane/ratelimit v0.1.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/evanphx/json-patch v5.9.11+incompatible // indirect
	github.com/exponent-io/jsonpath v0.0.0-20210407135951-1de76d718b3f // indirect
	github.com/extism/go-sdk v1.7.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fluxcd/cli-utils v1.2.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gaissmai/bart v0.26.1 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-logr/zapr v1.3.0 // indirect
	github.com/go-openapi/analysis v0.25.2 // indirect
	github.com/go-openapi/jsonpointer v0.23.1 // indirect
	github.com/go-openapi/jsonreference v0.21.6 // indirect
	github.com/go-openapi/runtime/server-middleware v0.30.0 // indirect
	github.com/go-openapi/swag/fileutils v0.26.1 // indirect
	github.com/go-openapi/swag/jsonname v0.26.1 // indirect
	github.com/go-openapi/swag/loading v0.26.1 // indirect
	github.com/go-openapi/swag/mangling v0.26.1 // indirect
	github.com/go-openapi/swag/netutils v0.26.1 // indirect
	github.com/go-openapi/swag/stringutils v0.26.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.26.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobuffalo/flect v1.0.3 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.18.0 // indirect
	github.com/godbus/dbus/v5 v5.2.0 // indirect
	github.com/gofrs/flock v0.13.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.1.7 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/licenseclassifier/v2 v2.0.0 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20250417193237-f615e6bd150b // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/kaptinlin/go-i18n v0.1.4 // indirect
	github.com/kaptinlin/jsonschema v0.4.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lib/pq v1.12.3 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/magefile/mage v1.17.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/spdystream v0.5.1 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/morikuni/aec v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/openshift/custom-resource-status v1.1.2 // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/petermattis/goid v0.0.0-20250813065127-a731cc31b4fe // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/rubenv/sql-migrate v1.8.1 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/segmentio/fasthash v1.0.3 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tetratelabs/wabin v0.0.0-20230304001439-f6f874872834 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	github.com/weppos/publicsuffix-go v0.30.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20230310154051-c8b263fd8300 // indirect
	github.com/zmap/zlint/v3 v3.5.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/dig v1.17.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/telemetry v0.0.0-20260610154732-fb80ec83bdd9 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	gomodules.xyz/jsonpatch/v2 v2.5.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260504160031-60b97b32f348 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiserver v0.36.2 // indirect
	k8s.io/code-generator v0.36.2 // indirect
	k8s.io/gengo/v2 v2.0.0-20250922181213-ec3ebc5fd46b // indirect
	k8s.io/kube-openapi v0.0.0-20260427204847-8949caaa1199 // indirect
	k8s.io/streaming v0.36.2 // indirect
	kubevirt.io/containerized-data-importer-api v1.63.1 // indirect
	kubevirt.io/controller-lifecycle-operator-sdk/api v0.0.0-20220329064328-f3cc58c6ed90 // indirect
	oras.land/oras-go/v2 v2.6.1 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
	sigs.k8s.io/controller-tools v0.20.1 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/kustomize/api v0.21.1 // indirect
	sigs.k8s.io/kustomize/kyaml v0.21.1 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.0 // indirect
)

// Enterprise dependencies.
//
// These must come after the OSS dependencies, since the go tooling adds
// new dependencies to the last require block without a doc comment.
//
// DO NOT REMOVE THE EMPTY LINE BETWEEN THIS BLOCK AND "require"!

// require (
// )
// Using private fork of controller-tools. See commit msg for more context
// as to why we are using a private fork.
replace sigs.k8s.io/controller-tools => github.com/cilium/controller-tools v0.21.0-1

// Using private fork for potential custom fixes and better control over versioning.
replace github.com/YutaroHayakawa/go-ra => github.com/isovalent/go-ra v0.0.0-20241125075947-1274124821d6

// controller-runtime v0.24 (matching k8s.io/* v0.36) is not yet released.
// Use a commit from main that includes the k8s v0.36 bump.
replace sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.23.1-0.20260331131016-598e330bda55

tool (
	github.com/AdamKorcz/go-118-fuzz-build/testing
	github.com/cilium/cilium/tools/dpgen
	github.com/cilium/deepequal-gen
	github.com/cilium/ebpf/cmd/bpf2go
	github.com/cilium/linters
	github.com/gogo/protobuf/gogoproto
	github.com/hmarr/codeowners/cmd/codeowners
	golang.org/x/tools/cmd/goimports
	golang.org/x/tools/go/analysis/analysistest
	golang.org/x/tools/go/analysis/singlechecker
	k8s.io/code-generator
	k8s.io/code-generator/cmd/client-gen
	k8s.io/code-generator/cmd/go-to-protobuf
	k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo
	k8s.io/code-generator/cmd/validation-gen
	sigs.k8s.io/controller-tools/cmd/controller-gen
)
