# kube-apiserver learning

基于1.18版本。源码：<https://github.com/kubernetes/kubernetes>

#### 启动入口

> cmd/kube-apiserver/apiserver.go

```
func main() {
    rand.Seed(time.Now().UnixNano())

    command := app.NewAPIServerCommand()

    // TODO: once we switch everything over to Cobra commands, we can go back to calling
    // utilflag.InitFlags() (by removing its pflag.Parse() call). For now, we have to set the
    // normalize func and add the go flag set by hand.
    // utilflag.InitFlags()
    logs.InitLogs()
    defer logs.FlushLogs()

    if err := command.Execute(); err != nil {
        os.Exit(1)
    }
}
```

主要是创建一个command,然后Execute该command.

#### command的创建

```
command := app.NewAPIServerCommand()
```

> k8s.io/kubernetes/cmd/kube-apiserver/app/server.go

```
// NewAPIServerCommand creates a *cobra.Command object with default parameters
func NewAPIServerCommand() *cobra.Command {
    s := options.NewServerRunOptions()
    cmd := &cobra.Command{
        Use: "kube-apiserver",
        Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,
        RunE: func(cmd *cobra.Command, args []string) error {
            verflag.PrintAndExitIfRequested()
            utilflag.PrintFlags(cmd.Flags())

            // set default options
            completedOptions, err := Complete(s)
            if err != nil {
                return err
            }

            // validate options
            if errs := completedOptions.Validate(); len(errs) != 0 {
                return utilerrors.NewAggregate(errs)
            }

            return Run(completedOptions, genericapiserver.SetupSignalHandler())
        },
    }

    fs := cmd.Flags()
    namedFlagSets := s.Flags()
    verflag.AddFlags(namedFlagSets.FlagSet("global"))
    globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name())
    options.AddCustomGlobalFlags(namedFlagSets.FlagSet("generic"))
    for _, f := range namedFlagSets.FlagSets {
        fs.AddFlagSet(f)
    }

    usageFmt := "Usage:\n  %s\n"
    cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
    cmd.SetUsageFunc(func(cmd *cobra.Command) error {
        fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
        cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
        return nil
    })
    cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
        fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
        cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
    })

    return cmd
}
```

app.NewAPIServerCommand()是干嘛的呢？

##### 首先，通过options.NewServerRunOptions，创建了apiserver的ServerRunOption；

> k8s.io/kubernetes/cmd/kube-apiserver/app/options/options.go

```
// ServerRunOptions runs a kubernetes api server.
type ServerRunOptions struct {
    GenericServerRunOptions *genericoptions.ServerRunOptions
    Etcd                    *genericoptions.EtcdOptions
    SecureServing           *genericoptions.SecureServingOptionsWithLoopback
    InsecureServing         *genericoptions.DeprecatedInsecureServingOptionsWithLoopback
    Audit                   *genericoptions.AuditOptions
    Features                *genericoptions.FeatureOptions
    Admission               *kubeoptions.AdmissionOptions
    Authentication          *kubeoptions.BuiltInAuthenticationOptions
    Authorization           *kubeoptions.BuiltInAuthorizationOptions
    CloudProvider           *kubeoptions.CloudProviderOptions
    APIEnablement           *genericoptions.APIEnablementOptions
    EgressSelector          *genericoptions.EgressSelectorOptions

    AllowPrivileged           bool
    EnableLogsHandler         bool
    EventTTL                  time.Duration
    KubeletConfig             kubeletclient.KubeletClientConfig
    KubernetesServiceNodePort int
    MaxConnectionBytesPerSec  int64
    // ServiceClusterIPRange is mapped to input provided by user
    ServiceClusterIPRanges string
    //PrimaryServiceClusterIPRange and SecondaryServiceClusterIPRange are the results
    // of parsing ServiceClusterIPRange into actual values
    PrimaryServiceClusterIPRange   net.IPNet
    SecondaryServiceClusterIPRange net.IPNet

    ServiceNodePortRange utilnet.PortRange
    SSHKeyfile           string
    SSHUser              string

    ProxyClientCertFile string
    ProxyClientKeyFile  string

    EnableAggregatorRouting bool

    MasterCount            int
    EndpointReconcilerType string

    ServiceAccountSigningKeyFile     string
    ServiceAccountIssuer             serviceaccount.TokenGenerator
    ServiceAccountTokenMaxExpiration time.Duration

    ShowHiddenMetricsForVersion string
}
```

```
// NewServerRunOptions creates a new ServerRunOptions object with default parameters
func NewServerRunOptions() *ServerRunOptions {
    s := ServerRunOptions{
        GenericServerRunOptions: genericoptions.NewServerRunOptions(),
        Etcd:                    genericoptions.NewEtcdOptions(storagebackend.NewDefaultConfig(kubeoptions.DefaultEtcdPathPrefix, nil)),
        SecureServing:           kubeoptions.NewSecureServingOptions(),
        InsecureServing:         kubeoptions.NewInsecureServingOptions(),
        Audit:                   genericoptions.NewAuditOptions(),
        Features:                genericoptions.NewFeatureOptions(),
        Admission:               kubeoptions.NewAdmissionOptions(),
        Authentication:          kubeoptions.NewBuiltInAuthenticationOptions().WithAll(),
        Authorization:           kubeoptions.NewBuiltInAuthorizationOptions(),
        CloudProvider:           kubeoptions.NewCloudProviderOptions(),
        APIEnablement:           genericoptions.NewAPIEnablementOptions(),
        EgressSelector:          genericoptions.NewEgressSelectorOptions(),

        EnableLogsHandler:      true,
        EventTTL:               1 * time.Hour,
        MasterCount:            1,
        EndpointReconcilerType: string(reconcilers.LeaseEndpointReconcilerType),
        KubeletConfig: kubeletclient.KubeletClientConfig{
            Port:         ports.KubeletPort,
            ReadOnlyPort: ports.KubeletReadOnlyPort,
            PreferredAddressTypes: []string{
                // --override-hostname
                string(api.NodeHostName),

                // internal, preferring DNS if reported
                string(api.NodeInternalDNS),
                string(api.NodeInternalIP),

                // external, preferring DNS if reported
                string(api.NodeExternalDNS),
                string(api.NodeExternalIP),
            },
            EnableHTTPS: true,
            HTTPTimeout: time.Duration(5) * time.Second,
        },
        ServiceNodePortRange: kubeoptions.DefaultServiceNodePortRange,
    }

    // Overwrite the default for storage data format.
    s.Etcd.DefaultStorageMediaType = "application/vnd.kubernetes.protobuf"

    return &s
}
```

options.NewServerRunOptions比较简单，只是用默认参数创建了一个新的ServerRunOptions对象。

##### 然后，通过complete函数设置apiserver默认运行参数，名为completedOptions；

```
completedOptions, err := Complete(s)
```

###### completedOptions生成过程

complete函数处理ServerRunOptions，生成completedServerRunOptions。complete函数必须在kube-apiserve flags处理后调用。

completedServerRunOptions及Complete函数定义如下

> k8s.io/kubernetes/cmd/kube-apiserver/app/server.go

```
// completedServerRunOptions is a private wrapper that enforces a call of Complete() before Run can be invoked.
type completedServerRunOptions struct {
    *options.ServerRunOptions
}
```

```
// Complete set default ServerRunOptions.
// Should be called after kube-apiserver flags parsed.
func Complete(s *options.ServerRunOptions) (completedServerRunOptions, error) {
    var options completedServerRunOptions
    // set defaults
    if err := s.GenericServerRunOptions.DefaultAdvertiseAddress(s.SecureServing.SecureServingOptions); err != nil {
        return options, err
    }
    if err := kubeoptions.DefaultAdvertiseAddress(s.GenericServerRunOptions, s.InsecureServing.DeprecatedInsecureServingOptions); err != nil {
        return options, err
    }

    // process s.ServiceClusterIPRange from list to Primary and Secondary
    // we process secondary only if provided by user
    apiServerServiceIP, primaryServiceIPRange, secondaryServiceIPRange, err := getServiceIPAndRanges(s.ServiceClusterIPRanges)
    if err != nil {
        return options, err
    }
    s.PrimaryServiceClusterIPRange = primaryServiceIPRange
    s.SecondaryServiceClusterIPRange = secondaryServiceIPRange

    if err := s.SecureServing.MaybeDefaultWithSelfSignedCerts(s.GenericServerRunOptions.AdvertiseAddress.String(), []string{"kubernetes.default.svc", "kubernetes.default", "kubernetes"}, []net.IP{apiServerServiceIP}); err != nil {
        return options, fmt.Errorf("error creating self-signed certificates: %v", err)
    }

    if len(s.GenericServerRunOptions.ExternalHost) == 0 {
        if len(s.GenericServerRunOptions.AdvertiseAddress) > 0 {
            s.GenericServerRunOptions.ExternalHost = s.GenericServerRunOptions.AdvertiseAddress.String()
        } else {
            if hostname, err := os.Hostname(); err == nil {
                s.GenericServerRunOptions.ExternalHost = hostname
            } else {
                return options, fmt.Errorf("error finding host name: %v", err)
            }
        }
        klog.Infof("external host was not specified, using %v", s.GenericServerRunOptions.ExternalHost)
    }

    s.Authentication.ApplyAuthorization(s.Authorization)

    // Use (ServiceAccountSigningKeyFile != "") as a proxy to the user enabling
    // TokenRequest functionality. This defaulting was convenient, but messed up
    // a lot of people when they rotated their serving cert with no idea it was
    // connected to their service account keys. We are taking this opportunity to
    // remove this problematic defaulting.
    if s.ServiceAccountSigningKeyFile == "" {
        // Default to the private server key for service account token signing
        if len(s.Authentication.ServiceAccounts.KeyFiles) == 0 && s.SecureServing.ServerCert.CertKey.KeyFile != "" {
            if kubeauthenticator.IsValidServiceAccountKeyFile(s.SecureServing.ServerCert.CertKey.KeyFile) {
                s.Authentication.ServiceAccounts.KeyFiles = []string{s.SecureServing.ServerCert.CertKey.KeyFile}
            } else {
                klog.Warning("No TLS key provided, service account token authentication disabled")
            }
        }
    }

    if s.ServiceAccountSigningKeyFile != "" && s.Authentication.ServiceAccounts.Issuer != "" {
        sk, err := keyutil.PrivateKeyFromFile(s.ServiceAccountSigningKeyFile)
        if err != nil {
            return options, fmt.Errorf("failed to parse service-account-issuer-key-file: %v", err)
        }
        if s.Authentication.ServiceAccounts.MaxExpiration != 0 {
            lowBound := time.Hour
            upBound := time.Duration(1<<32) * time.Second
            if s.Authentication.ServiceAccounts.MaxExpiration < lowBound ||
                s.Authentication.ServiceAccounts.MaxExpiration > upBound {
                return options, fmt.Errorf("the serviceaccount max expiration must be between 1 hour to 2^32 seconds")
            }
        }

        s.ServiceAccountIssuer, err = serviceaccount.JWTTokenGenerator(s.Authentication.ServiceAccounts.Issuer, sk)
        if err != nil {
            return options, fmt.Errorf("failed to build token generator: %v", err)
        }
        s.ServiceAccountTokenMaxExpiration = s.Authentication.ServiceAccounts.MaxExpiration
    }

    if s.Etcd.EnableWatchCache {
        klog.V(2).Infof("Initializing cache sizes based on %dMB limit", s.GenericServerRunOptions.TargetRAMMB)
        sizes := cachesize.NewHeuristicWatchCacheSizes(s.GenericServerRunOptions.TargetRAMMB)
        if userSpecified, err := serveroptions.ParseWatchCacheSizes(s.Etcd.WatchCacheSizes); err == nil {
            for resource, size := range userSpecified {
                sizes[resource] = size
            }
        }
        s.Etcd.WatchCacheSizes, err = serveroptions.WriteWatchCacheSizes(sizes)
        if err != nil {
            return options, err
        }
    }

    if s.APIEnablement.RuntimeConfig != nil {
        for key, value := range s.APIEnablement.RuntimeConfig {
            if key == "v1" || strings.HasPrefix(key, "v1/") ||
                key == "api/v1" || strings.HasPrefix(key, "api/v1/") {
                delete(s.APIEnablement.RuntimeConfig, key)
                s.APIEnablement.RuntimeConfig["/v1"] = value
            }
            if key == "api/legacy" {
                delete(s.APIEnablement.RuntimeConfig, key)
            }
        }
    }
    options.ServerRunOptions = s
    return options, nil
}
```

##### 最后，返回run函数，run函数加载completedOptions及genericapiserver.SetupSignalHandler()参数。run函数即为**command**主体，为Execute的对象；

```
return Run(completedOptions, genericapiserver.SetupSignalHandler())
```

###### genericapiserver.SetupSignalHandler()生成过程

> k8s.io/apiserver/pkg/server/signal.go

```
// SetupSignalHandler registered for SIGTERM and SIGINT. A stop channel is returned
// which is closed on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func SetupSignalHandler() <-chan struct{} {
    close(onlyOneSignalHandler) // panics when called twice

    shutdownHandler = make(chan os.Signal, 2)

    stop := make(chan struct{})
    signal.Notify(shutdownHandler, shutdownSignals...)
    go func() {
        <-shutdownHandler
        close(stop)
        <-shutdownHandler
        os.Exit(1) // second signal. Exit directly.
    }()

    return stop
}
```

可以发现genericapiserver.SetupSignalHandler()主要用来给Run函数传递一个channel,用来接收shutdownSignals....

#### cmd/kube-apiserver/app/server.go Run函数

> k8s.io/kubernetes/cmd/kube-apiserver/app/server.go

```
// Run runs the specified APIServer. This should never exit.
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
 // To help debugging, immediately log version
 klog.Infof("Version: %+v", version.Get()) 
server, err := CreateServerChain(completeOptions, stopCh)
 if err != nil {
 return err
 } 
prepared, err := server.PrepareRun()
 if err != nil {
 return err
 } 
return prepared.Run(stopCh)
}
```

**首先调用CreateServerChain函数，该函数目的是生成server结构体，类型为APIAggregator。**

```
server, err := CreateServerChain(completeOptions, stopCh)
```

CreateServerChain函数定义为

> k8s.io/kubernetes/cmd/kube-apiserver/app/server.go

```
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
    nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
    if err != nil {
        return nil, err
    }

    kubeAPIServerConfig, insecureServingInfo, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
    if err != nil {
        return nil, err
    }

    // If additional API servers are added, they should be gated.
    apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
        serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig))
    if err != nil {
        return nil, err
    }
    apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
    if err != nil {
        return nil, err
    }

    kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
    if err != nil {
        return nil, err
    }

    // aggregator comes last in the chain
    aggregatorConfig, err := createAggregatorConfig(*kubeAPIServerConfig.GenericConfig, completedOptions.ServerRunOptions, kubeAPIServerConfig.ExtraConfig.VersionedInformers, serviceResolver, proxyTransport, pluginInitializer)
    if err != nil {
        return nil, err
    }
    aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers)
    if err != nil {
        // we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
        return nil, err
    }

    if insecureServingInfo != nil {
        insecureHandlerChain := kubeserver.BuildInsecureHandlerChain(aggregatorServer.GenericAPIServer.UnprotectedHandler(), kubeAPIServerConfig.GenericConfig)
        if err := insecureServingInfo.Serve(insecureHandlerChain, kubeAPIServerConfig.GenericConfig.RequestTimeout, stopCh); err != nil {
            return nil, err
        }
    }

    return aggregatorServer, nil
}
```

APIAggregator定义为

> k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

```
// APIAggregator contains state for a Kubernetes cluster master/api server.
type APIAggregator struct {
    GenericAPIServer *genericapiserver.GenericAPIServer

    delegateHandler http.Handler

    // proxyClientCert/Key are the client cert used to identify this proxy. Backing APIServices use
    // this to confirm the proxy's identity
    proxyClientCert []byte
    proxyClientKey  []byte
    proxyTransport  *http.Transport

    // proxyHandlers are the proxy handlers that are currently registered, keyed by apiservice.name
    proxyHandlers map[string]*proxyHandler
    // handledGroups are the groups that already have routes
    handledGroups sets.String

    // lister is used to add group handling for /apis/<group> aggregator lookups based on
    // controller state
    lister listers.APIServiceLister

    // provided for easier embedding
    APIRegistrationInformers informers.SharedInformerFactory

    // Information needed to determine routing for the aggregator
    serviceResolver ServiceResolver

    // Enable swagger and/or OpenAPI if these configs are non-nil.
    openAPIConfig *openapicommon.Config

    // openAPIAggregationController downloads and merges OpenAPI specs.
    openAPIAggregationController *openapicontroller.AggregationController

    // egressSelector selects the proper egress dialer to communicate with the custom apiserver
    // overwrites proxyTransport dialer if not nil
    egressSelector *egressselector.EgressSelector
}
```

**生成server（APIAggregator类型）后，调用PrepareRun（)方法生成preparedAPIAggregator**

```
prepared, err := server.PrepareRun()
```

> k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

```
// PrepareRun prepares the aggregator to run, by setting up the OpenAPI spec and calling
// the generic PrepareRun.
func (s *APIAggregator) PrepareRun() (preparedAPIAggregator, error) {
    // add post start hook before generic PrepareRun in order to be before /healthz installation
    if s.openAPIConfig != nil {
        s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapi-controller", func(context genericapiserver.PostStartHookContext) error {
            go s.openAPIAggregationController.Run(context.StopCh)
            return nil
        })
    }

    prepared := s.GenericAPIServer.PrepareRun()

    // delay OpenAPI setup until the delegate had a chance to setup their OpenAPI handlers
    if s.openAPIConfig != nil {
        specDownloader := openapiaggregator.NewDownloader()
        openAPIAggregator, err := openapiaggregator.BuildAndRegisterAggregator(
            &specDownloader,
            s.GenericAPIServer.NextDelegate(),
            s.GenericAPIServer.Handler.GoRestfulContainer.RegisteredWebServices(),
            s.openAPIConfig,
            s.GenericAPIServer.Handler.NonGoRestfulMux)
        if err != nil {
            return preparedAPIAggregator{}, err
        }
        s.openAPIAggregationController = openapicontroller.NewAggregationController(&specDownloader, openAPIAggregator)
    }

    return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil
}
```

preparedAPIAggregator定义为

> k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

```
// preparedGenericAPIServer is a private wrapper that enforces a call of PrepareRun() before Run can be invoked.
type preparedAPIAggregator struct {
    *APIAggregator
    runnable runnable
}
```

```
type runnable interface {
    Run(stopCh <-chan struct{}) error
}
```

preparedAPIAggregator实际上是在APIAggregator基础上，包装了runable类型的interface 
该interface 有Run方法。

preparedAPIAggregator具体是怎么生成的呢，查看APIAggregator的PrepareRun()方法发现有如下两句

```
prepared := s.GenericAPIServer.PrepareRun()
```

```
return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil
```

**可以发现preparedAPIAggregator中runnable为prepared,实际为 APIAggregator.GenericAPIServer.PrepareRun()函数返回值,是一个结构体，类型为preparedGenericAPIServer**

GenericAPIServer及PrepareRun方法定义为

> k8s.io/apiserver/pkg/server/genericapiserver.go

```
// GenericAPIServer contains state for a Kubernetes cluster api server.
type GenericAPIServer struct {
    // discoveryAddresses is used to build cluster IPs for discovery.
    discoveryAddresses discovery.Addresses

    // LoopbackClientConfig is a config for a privileged loopback connection to the API server
    LoopbackClientConfig *restclient.Config

    // minRequestTimeout is how short the request timeout can be.  This is used to build the RESTHandler
    minRequestTimeout time.Duration

    // ShutdownTimeout is the timeout used for server shutdown. This specifies the timeout before server
    // gracefully shutdown returns.
    ShutdownTimeout time.Duration

    // legacyAPIGroupPrefixes is used to set up URL parsing for authorization and for validating requests
    // to InstallLegacyAPIGroup
    legacyAPIGroupPrefixes sets.String

    // admissionControl is used to build the RESTStorage that backs an API Group.
    admissionControl admission.Interface

    // SecureServingInfo holds configuration of the TLS server.
    SecureServingInfo *SecureServingInfo

    // ExternalAddress is the address (hostname or IP and port) that should be used in
    // external (public internet) URLs for this GenericAPIServer.
    ExternalAddress string

    // Serializer controls how common API objects not in a group/version prefix are serialized for this server.
    // Individual APIGroups may define their own serializers.
    Serializer runtime.NegotiatedSerializer

    // "Outputs"
    // Handler holds the handlers being used by this API server
    Handler *APIServerHandler

    // listedPathProvider is a lister which provides the set of paths to show at /
    listedPathProvider routes.ListedPathProvider

    // DiscoveryGroupManager serves /apis
    DiscoveryGroupManager discovery.GroupManager

    // Enable swagger and/or OpenAPI if these configs are non-nil.
    openAPIConfig *openapicommon.Config

    // OpenAPIVersionedService controls the /openapi/v2 endpoint, and can be used to update the served spec.
    // It is set during PrepareRun.
    OpenAPIVersionedService *handler.OpenAPIService

    // StaticOpenAPISpec is the spec derived from the restful container endpoints.
    // It is set during PrepareRun.
    StaticOpenAPISpec *spec.Swagger

    // PostStartHooks are each called after the server has started listening, in a separate go func for each
    // with no guarantee of ordering between them.  The map key is a name used for error reporting.
    // It may kill the process with a panic if it wishes to by returning an error.
    postStartHookLock      sync.Mutex
    postStartHooks         map[string]postStartHookEntry
    postStartHooksCalled   bool
    disabledPostStartHooks sets.String

    preShutdownHookLock    sync.Mutex
    preShutdownHooks       map[string]preShutdownHookEntry
    preShutdownHooksCalled bool

    // healthz checks
    healthzLock            sync.Mutex
    healthzChecks          []healthz.HealthChecker
    healthzChecksInstalled bool
    // livez checks
    livezLock            sync.Mutex
    livezChecks          []healthz.HealthChecker
    livezChecksInstalled bool
    // readyz checks
    readyzLock            sync.Mutex
    readyzChecks          []healthz.HealthChecker
    readyzChecksInstalled bool
    livezGracePeriod      time.Duration
    livezClock            clock.Clock
    // the readiness stop channel is used to signal that the apiserver has initiated a shutdown sequence, this
    // will cause readyz to return unhealthy.
    readinessStopCh chan struct{}

    // auditing. The backend is started after the server starts listening.
    AuditBackend audit.Backend

    // Authorizer determines whether a user is allowed to make a certain request. The Handler does a preliminary
    // authorization check using the request URI but it may be necessary to make additional checks, such as in
    // the create-on-update case
    Authorizer authorizer.Authorizer

    // EquivalentResourceRegistry provides information about resources equivalent to a given resource,
    // and the kind associated with a given resource. As resources are installed, they are registered here.
    EquivalentResourceRegistry runtime.EquivalentResourceRegistry

    // enableAPIResponseCompression indicates whether API Responses should support compression
    // if the client requests it via Accept-Encoding
    enableAPIResponseCompression bool

    // delegationTarget is the next delegate in the chain. This is never nil.
    delegationTarget DelegationTarget

    // HandlerChainWaitGroup allows you to wait for all chain handlers finish after the server shutdown.
    HandlerChainWaitGroup *utilwaitgroup.SafeWaitGroup

    // ShutdownDelayDuration allows to block shutdown for some time, e.g. until endpoints pointing to this API server
    // have converged on all node. During this time, the API server keeps serving, /healthz will return 200,
    // but /readyz will return failure.
    ShutdownDelayDuration time.Duration

    // The limit on the request body size that would be accepted and decoded in a write request.
    // 0 means no limit.
    maxRequestBodyBytes int64
}
```

```
// PrepareRun does post API installation setup steps. It calls recursively the same function of the delegates.
func (s *GenericAPIServer) PrepareRun() preparedGenericAPIServer {
    s.delegationTarget.PrepareRun()

    if s.openAPIConfig != nil {
        s.OpenAPIVersionedService, s.StaticOpenAPISpec = routes.OpenAPI{
            Config: s.openAPIConfig,
        }.Install(s.Handler.GoRestfulContainer, s.Handler.NonGoRestfulMux)
    }

    s.installHealthz()
    s.installLivez()
    err := s.addReadyzShutdownCheck(s.readinessStopCh)
    if err != nil {
        klog.Errorf("Failed to install readyz shutdown check %s", err)
    }
    s.installReadyz()

    // Register audit backend preShutdownHook.
    if s.AuditBackend != nil {
        err := s.AddPreShutdownHook("audit-backend", func() error {
            s.AuditBackend.Shutdown()
            return nil
        })
        if err != nil {
            klog.Errorf("Failed to add pre-shutdown hook for audit-backend %s", err)
        }
    }

    return preparedGenericAPIServer{s}
}
```

```
// preparedGenericAPIServer is a private wrapper that enforces a call of PrepareRun() before Run can be invoked.
type preparedGenericAPIServer struct {
    *GenericAPIServer
}
```

可以发现preparedAPIAggregator其实是在APIAggregator基础上，包装了preparedGenericAPIServer

**preparedAPIAggregator生成后，调用preparedAPIAggregator的Run()方法**

```
return prepared.Run(stopCh)
```

> k8s.io/apiserver/pkg/server/genericapiserver.go

```
func (s preparedAPIAggregator) Run(stopCh <-chan struct{}) error {
    return s.runnable.Run(stopCh)
}
```

返回preparedAPIAggregator.runmable的Run方法, 实际最终返回preparedGenericAPIServer的run方法

> k8s.io/apiserver/pkg/server/genericapiserver.go

```
// Run spawns the secure http server. It only returns if stopCh is closed
// or the secure port cannot be listened on initially.
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
    delayedStopCh := make(chan struct{})

    go func() {
        defer close(delayedStopCh)

        <-stopCh

        // As soon as shutdown is initiated, /readyz should start returning failure.
        // This gives the load balancer a window defined by ShutdownDelayDuration to detect that /readyz is red
        // and stop sending traffic to this server.
        close(s.readinessStopCh)

        time.Sleep(s.ShutdownDelayDuration)
    }()

    // close socket after delayed stopCh
    err := s.NonBlockingRun(delayedStopCh)
    if err != nil {
        return err
    }

    <-stopCh

    // run shutdown hooks directly. This includes deregistering from the kubernetes endpoint in case of kube-apiserver.
    err = s.RunPreShutdownHooks()
    if err != nil {
        return err
    }

    // wait for the delayed stopCh before closing the handler chain (it rejects everything after Wait has been called).
    <-delayedStopCh

    // Wait for all requests to finish, which are bounded by the RequestTimeout variable.
    s.HandlerChainWaitGroup.Wait()

    return nil
}
```

**cmd/kube-apiserver/app/server.go run函数总结**

- server, err := CreateServerChain(completeOptions, stopCh)
  作用为是生成server结构体，类型为APIAggregator

- prepared, err := server.PrepareRun()
  作用为处理APIAggreator 生成 preparedAPIAggreator 结构体，该结构体是对APIAggreator的包装，增加了runable (GenericAPIServer)。
  并执行了GenericAPIServer的PrepareRun方法。（确保PrepareRun能够在下面的run前执行）

- return prepared.Run(stopCh)
  作用为执行preparedGenericAPIServer的run方法（preparedGenericAPIServer为GenericAPIServer的包装）

#### preparedGenericAPIServer的run方法

主要是调用preparedGenericAPIServer 的NonBlockingRun方法

```
err := s.NonBlockingRun(delayedStopCh)
```

> k8s.io/apiserver/pkg/server/genericapiserver.go

```go
// NonBlockingRun spawns the secure http server. An error is
// returned if the secure port cannot be listened on.
func (s preparedGenericAPIServer) NonBlockingRun(stopCh <-chan struct{}) error {
    // Use an stop channel to allow graceful shutdown without dropping audit events
    // after http server shutdown.
    auditStopCh := make(chan struct{})

    // Start the audit backend before any request comes in. This means we must call Backend.Run
    // before http server start serving. Otherwise the Backend.ProcessEvents call might block.
    if s.AuditBackend != nil {
        if err := s.AuditBackend.Run(auditStopCh); err != nil {
            return fmt.Errorf("failed to run the audit backend: %v", err)
        }
    }

    // Use an internal stop channel to allow cleanup of the listeners on error.
    internalStopCh := make(chan struct{})
    var stoppedCh <-chan struct{}
    if s.SecureServingInfo != nil && s.Handler != nil {
        var err error
        stoppedCh, err = s.SecureServingInfo.Serve(s.Handler, s.ShutdownTimeout, internalStopCh)
        if err != nil {
            close(internalStopCh)
            close(auditStopCh)
            return err
        }
    }

    // Now that listener have bound successfully, it is the
    // responsibility of the caller to close the provided channel to
    // ensure cleanup.
    go func() {
        <-stopCh
        close(internalStopCh)
        if stoppedCh != nil {
            <-stoppedCh
        }
        s.HandlerChainWaitGroup.Wait()
        close(auditStopCh)
    }()

    s.RunPostStartHooks(stopCh)

    if _, err := systemd.SdNotify(true, "READY=1\n"); err != nil {
        klog.Errorf("Unable to send systemd daemon successful start message: %v\n", err)
    }

    return nil
}
```

```go
stoppedCh, err = s.SecureServingInfo.Serve(s.Handler, s.ShutdownTimeout, internalStopCh)
```

preparedGenericAPIServer.SecureServingInfo 类型为*SecureServingInfo

> k8s.io/apiserver/pkg/server/config.go

```go
type SecureServingInfo struct {
	// Listener is the secure server network listener.
	Listener net.Listener

	// Cert is the main server cert which is used if SNI does not match. Cert must be non-nil and is
	// allowed to be in SNICerts.
	Cert dynamiccertificates.CertKeyContentProvider

	// SNICerts are the TLS certificates used for SNI.
	SNICerts []dynamiccertificates.SNICertKeyContentProvider

	// ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
	ClientCA dynamiccertificates.CAContentProvider

	// MinTLSVersion optionally overrides the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MinTLSVersion uint16

	// CipherSuites optionally overrides the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	CipherSuites []uint16

	// HTTP2MaxStreamsPerConnection is the limit that the api server imposes on each client.
	// A value of zero means to use the default provided by golang's HTTP/2 support.
	HTTP2MaxStreamsPerConnection int

	// DisableHTTP2 indicates that http2 should not be enabled.
	DisableHTTP2 bool
}
```

> k8s.io/apiserver/pkg/server/secure_serving.go

```go
// Serve runs the secure http server. It fails only if certificates cannot be loaded or the initial listen call fails.
// The actual server loop (stoppable by closing stopCh) runs in a go routine, i.e. Serve does not block.
// It returns a stoppedCh that is closed when all non-hijacked active requests have been processed.
func (s *SecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, error) {
	if s.Listener == nil {
		return nil, fmt.Errorf("listener must not be nil")
	}

	tlsConfig, err := s.tlsConfig(stopCh)
	if err != nil {
		return nil, err
	}

	secureServer := &http.Server{
		Addr:           s.Listener.Addr().String(),
		Handler:        handler,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      tlsConfig,
	}

	// At least 99% of serialized resources in surveyed clusters were smaller than 256kb.
	// This should be big enough to accommodate most API POST requests in a single frame,
	// and small enough to allow a per connection buffer of this size multiplied by `MaxConcurrentStreams`.
	const resourceBody99Percentile = 256 * 1024

	http2Options := &http2.Server{}

	// shrink the per-stream buffer and max framesize from the 1MB default while still accommodating most API POST requests in a single frame
	http2Options.MaxUploadBufferPerStream = resourceBody99Percentile
	http2Options.MaxReadFrameSize = resourceBody99Percentile

	// use the overridden concurrent streams setting or make the default of 250 explicit so we can size MaxUploadBufferPerConnection appropriately
	if s.HTTP2MaxStreamsPerConnection > 0 {
		http2Options.MaxConcurrentStreams = uint32(s.HTTP2MaxStreamsPerConnection)
	} else {
		http2Options.MaxConcurrentStreams = 250
	}

	// increase the connection buffer size from the 1MB default to handle the specified number of concurrent streams
	http2Options.MaxUploadBufferPerConnection = http2Options.MaxUploadBufferPerStream * int32(http2Options.MaxConcurrentStreams)

	if !s.DisableHTTP2 {
		// apply settings to the server
		if err := http2.ConfigureServer(secureServer, http2Options); err != nil {
			return nil, fmt.Errorf("error configuring http2: %v", err)
		}
	}

	klog.Infof("Serving securely on %s", secureServer.Addr)
	return RunServer(secureServer, s.Listener, shutdownTimeout, stopCh)
}
```
