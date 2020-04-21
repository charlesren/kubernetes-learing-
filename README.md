# kubernetes-learning

kubernetes-learning notes 

kubernetes version: 1.18



**小知识**

kubernetes会把部分k8s.io/开头的包解析到staging/src,例如

> "k8s.io/client-go/dynamic" // resolves to staging/src/k8s.io/client-go/dynamic

详见<https://github.com/kubernetes/kubernetes/tree/master/staging>

项目目录结构参考<https://www.jianshu.com/p/dee1da6fd51b>