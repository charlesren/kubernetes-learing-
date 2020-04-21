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

> k8s.io/kubernetes/cmd/kube-apiserver/app

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

##### 首先，通过options.NewServerRunOptions，创建了apiserver的ServerRunOption；

> k8s.io/kubernetes/cmd/kube-apiserver/app/options

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

##### 然后，通过complete函数设置apiserver默认运行参数，名为completedOptions；



最后，返回run函数，run函数加载completedOptions及genericapiserver.SetupSignalHandler()参数。run函数即为**command**主体，为Execute的对象；

###### completedOptions生成过程

> cmd/kube-apiserver/app/options/options.go

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

options.NewServerRunOptions比较简单，只是用默认参数创建了一个新的ServerRunOptions对象。

complete函数处理ServerRunOptions，生成completedServerRunOptions。complete函数必须在kube-apiserve flags处理后调用。

completedServerRunOptions定于如下

> cmd/kube-apiserver/app/server.go

```
// completedServerRunOptions is a private wrapper that enforces a call of Complete() before Run can be invoked.
type completedServerRunOptions struct {
    *options.ServerRunOptions
}
```

> cmd/kube-apiserver/app/server.go

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

###### genericapiserver.SetupSignalHandler()生成过程

genericapiserver 即为"k8s.io/apiserver/pkg/server"  包

该包staging在如下目录

> staging/src/k8s.io/apiserver/pkg/server/signal.go

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

#### Run函数

> cmd/kube-apiserver/app/server.go

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
APIAggregator定义在k8s.io/kube-aggregator/pkg/apiserver,staging在

> staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

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

> cmd/kube-apiserver/app/server.go

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

生成server（APIAggregator类型）后，调用PrepareRun（)方法生成preparedAPIAggregator
preparedAPIAggregator定义如下：

> staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

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

实际上是在APIAggregator基础上，包装了runable类型的interface .
该interface 有Run方法。

> staging/src/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go

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

从prepared := s.GenericAPIServer.PrepareRun()及return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil发现
**preparedAPIAggregator中runnable为prepared,实际为 APIAggregator.GenericAPIServer.PrepareRun()函数返回值,是一个结构体，类型为*GenericAPIServer**
**runnable才是真命天子**
结构体定义及PrepareRun函数如下

> staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go

```
// preparedGenericAPIServer is a private wrapper that enforces a call of PrepareRun() before Run can be invoked.
type preparedGenericAPIServer struct {
    *GenericAPIServer
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

**可以发现，prepared, err := server.PrepareRun()  最终通过处理APIAggreator 生成 preparedGenericAPIServer，是GenericAPIServe的包装**

preparedAPIAggregator生成后，调用preparedAPIAggregator的Run()方法

```
func (s preparedAPIAggregator) Run(stopCh <-chan struct{}) error {
    return s.runnable.Run(stopCh)
}
```

实际返回preparedAPIAggregator.runmable的Run方法,即preparedGenericAPIServer的run方法

>  staging/src/k8s.io/apiserver/pkg/server/genericapiserver.go

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

#### run函数总结

server, err := CreateServerChain(completeOptions, stopCh)
作用为是生成server结构体，类型为APIAggregator

prepared, err := server.PrepareRun()
作用为处理APIAggreator 生成 preparedAPIAggreator 结构体，该结构体是对APIAggreator的包装，增加了runable (GenericAPIServer)。
并执行了GenericAPIServer的PrepareRun方法。（确保PrepareRun能够在下面的run前执行）

return prepared.Run(stopCh)
作用为执行preparedGenericAPIServer的run方法（preparedGenericAPIServer为GenericAPIServer的包装）
