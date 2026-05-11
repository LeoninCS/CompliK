# ProcScan 权限需求说明

本文档说明 ProcScan 为完成当前代码中的完整逻辑所需的 Kubernetes RBAC 权限、Pod 运行权限和相关集群准入条件。结论基于当前实现与部署清单：

- 进程扫描：读取宿主机 `/proc`，解析 `cmdline`、`status`、`cgroup`。
- 容器元数据解析：通过节点上的 CRI socket 调用 `ContainerStatus`，从容器 label 中获取 Pod 名称和命名空间。
- 告警：向 Lark/飞书 webhook 发送 HTTP 请求。
- 自动处置：可选地给命中的 Namespace 写入标签。
- 指标：可选地暴露 Prometheus `/metrics` HTTP 端点。

## 总览

| 能力 | 是否必需 | 权限类型 | 说明 |
| --- | --- | --- | --- |
| 扫描本节点所有进程 | 必需 | Pod 权限 | 需要以 DaemonSet 在每个目标节点运行，挂载宿主机 `/proc`。 |
| 读取其他 UID/宿主机进程信息 | 建议必需 | Linux capabilities | 建议保留 `SYS_PTRACE` 和 `DAC_READ_SEARCH`，否则在部分节点配置下可能读不到 `/proc/<pid>/cmdline`、`status` 或 `cgroup`。 |
| 识别 Pod/Namespace | 必需，若需要完整告警上下文 | Pod 权限 | 需要挂载并访问节点 CRI socket，例如 containerd socket。 |
| Namespace 打标 | 仅 `actions.label.enabled=true` 时必需 | RBAC | 当前代码使用 Namespace `get` 和 `update`。 |
| Lark/飞书告警 | webhook 配置后必需 | 网络能力 | 需要 Pod 能访问外部 webhook 地址和 DNS。 |
| Prometheus metrics | `metrics.enabled=true` 时必需 | 网络/服务发现 | 需要暴露容器端口；创建 `ServiceMonitor`/`PrometheusRule` 是部署者权限，不是 ProcScan 运行时 RBAC。 |

## 运行时 RBAC

ProcScan 运行时 Kubernetes API 只用于 Namespace 打标。代码路径是：

- `internal/core/k8s/client.go`
  - `CoreV1().Namespaces().Get(...)`
  - `CoreV1().Namespaces().Update(...)`
- `internal/core/scanner/scanner.go`
  - 在发现可疑进程后，如果 `actions.label.enabled=true`，调用 `LabelNamespace(...)`。

因此，完整自动处置逻辑需要以下最小 RBAC：

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: block-procscan
  namespace: block-system
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: block-procscan
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: block-procscan
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: block-procscan
subjects:
  - kind: ServiceAccount
    name: block-procscan
    namespace: block-system
```

注意事项：

- 当前实现是 `Update` Namespace 对象，不是 `Patch`，所以只授予 `patch` 不够。
- 不需要 `pods`、`nodes`、`events`、`secrets`、`configmaps`、`deployments` 等资源的运行时访问权限。
- 如果只做进程扫描和告警，且 `actions.label.enabled=false`，ProcScan 不需要 Kubernetes API RBAC；不过当前部署仍会挂载 ServiceAccount token，让客户端能够初始化。
- 如果关闭 ServiceAccount token 自动挂载，`rest.InClusterConfig()` 会失败，Namespace 打标不可用，但本地进程扫描、CRI 元数据解析和 webhook 告警仍可继续工作，前提是对应 Pod 权限和网络可用。

## Pod 权限与安全上下文

ProcScan 需要节点级视角，应该以 DaemonSet 部署到每个需要扫描的节点。当前不需要容器 `privileged: true`，但需要 hostPath、hostPID 和额外 capabilities，这在 Kubernetes Pod Security Standards 中通常属于 `privileged` 级别的准入能力。

建议的 Pod/容器安全上下文：

```yaml
spec:
  hostNetwork: false
  hostPID: true
  serviceAccountName: block-procscan
  securityContext:
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups:
      - 0
  containers:
    - name: scanner
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        capabilities:
          drop:
            - ALL
          add:
            - SYS_PTRACE
            - DAC_READ_SEARCH
      volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: containerd-sock
          mountPath: /var/run/containerd/containerd.sock
          readOnly: false
  volumes:
    - name: proc
      hostPath:
        path: /proc
        type: Directory
    - name: containerd-sock
      hostPath:
        path: /var/run/containerd/containerd.sock
        type: Socket
```

### `hostPID`

`hostPID: true` 让 Pod 加入宿主机 PID namespace，符合 ProcScan 的节点级进程扫描模型。当前代码主要读取挂载进来的 `/host/proc`，但保留 `hostPID` 可以减少不同运行时、内核和 `/proc` 挂载配置下的可见性差异。

如果去掉 `hostPID`，某些环境中仍可能通过 `/host/proc` 读到宿主机进程，但这不应作为完整能力的默认假设。

### `/proc` hostPath

`scanner.proc_path` 默认指向 `/host/proc`，所以必须把宿主机 `/proc` 只读挂载到同一路径。ProcScan 会读取：

- `/host/proc` 下的 PID 目录列表。
- `/host/proc/<pid>/cmdline`，用于进程名和命令行规则匹配。
- `/host/proc/<pid>/status`，用于 `NSpid`、`PPid` 等进程关系分析。
- `/host/proc/<pid>/cgroup`，用于提取 container ID。

该挂载建议保持 `readOnly: true`，当前逻辑不需要写宿主机 `/proc`。

### CRI socket

ProcScan 通过 CRI `ContainerStatus` 查询容器 labels，用于把 container ID 还原成 Pod 名称和 Namespace。当前代码会尝试这些 socket：

- `/var/run/containerd/containerd.sock`
- `/run/containerd/containerd.sock`
- `/var/run/crio/crio.sock`
- `/var/run/dockershim.sock`

部署时必须按节点实际运行时挂载对应 socket，并保持容器内路径与代码尝试的路径一致。当前 manifest 挂载的是：

```yaml
hostPath:
  path: /var/run/containerd/containerd.sock
  type: Socket
mountPath: /var/run/containerd/containerd.sock
```

如果集群使用 CRI-O，需要改为挂载 `/var/run/crio/crio.sock`；如果 containerd socket 在 `/run/containerd/containerd.sock`，也需要同步挂载该路径。

socket 权限通常由宿主机文件权限决定。当前清单使用非 root 用户 `65532`，同时设置 `supplementalGroups: [0]`，用于兼容常见的 `root:root` socket 组权限。如果节点 socket 属于其他 GID，应把对应 GID 加入 `supplementalGroups`。

### capabilities

当前建议保留：

- `SYS_PTRACE`：读取其他进程的 `/proc` 信息时可能触发 ptrace 访问检查，尤其是跨 UID、宿主机进程或内核启用更严格保护时。
- `DAC_READ_SEARCH`：绕过文件读权限和目录搜索权限，用于提高读取宿主机 `/proc` 条目的稳定性。

当前不需要：

- `SYS_ADMIN`
- `NET_ADMIN`
- `BPF`
- `SYS_MODULE`
- 容器 `privileged: true`

如果节点 `/proc` 配置宽松、进程同 UID 可读，去掉这些 capabilities 可能仍能部分工作；但为了完成“扫描本节点全部目标进程并识别容器归属”的完整逻辑，不建议移除。

### Pod Security Admission / PSP / SCC

即使容器设置了 `privileged: false`，以下配置也通常不能通过 `restricted` 或 `baseline` Pod Security：

- `hostPID: true`
- `hostPath` 挂载宿主机 `/proc`
- `hostPath` 挂载容器运行时 socket
- 添加 `SYS_PTRACE`、`DAC_READ_SEARCH`

因此 ProcScan 所在命名空间需要被允许创建这类节点级安全 Pod。常见方式包括：

- 对命名空间设置 `pod-security.kubernetes.io/enforce=privileged`，或使用集群级豁免。
- 在 OpenShift 中绑定允许 hostPath、hostPID 和所需 capabilities 的 SCC。
- 在仍使用 PSP 的旧集群中，授予允许 hostPID、hostPath 和 capabilities 的 PSP。

这不是要求容器本身以 `privileged: true` 运行，而是要求准入策略允许这些节点级能力。

## 网络权限

ProcScan 不需要 `hostNetwork`。当前清单中 `hostNetwork: false` 是合理的。

需要确保网络策略允许：

- Pod 访问 Kubernetes API Server：仅 Namespace 打标需要。
- Pod 访问 Lark/飞书 webhook 地址：仅配置 webhook 后需要。
- Prometheus 或监控组件访问 ProcScan metrics 端口：仅 `metrics.enabled=true` 时需要。
- DNS 解析：访问外部 webhook 时通常需要。

如果集群启用了默认拒绝的 `NetworkPolicy`，需要显式放通上述出站和入站流量。

## 部署者需要的权限

以下不是 ProcScan Pod 运行时权限，而是执行安装清单或 Helm Chart 的用户需要具备的权限。

基础安装通常需要能创建或更新：

- `Namespace`
- `ServiceAccount`
- `ClusterRole`
- `ClusterRoleBinding`
- `ConfigMap`
- `DaemonSet`
- `Service`

如果部署 `procscan/deploy/manifests/servicemonitor.yaml`，还需要能创建：

- `monitoring.coreos.com/v1` 的 `ServiceMonitor`
- `monitoring.coreos.com/v1` 的 `PrometheusRule`

并且集群中需要已安装 Prometheus Operator 对应 CRD，否则这些资源无法创建。

## 最小运行模式对比

| 模式 | RBAC | Pod 权限 | 结果 |
| --- | --- | --- | --- |
| 仅扫描并本地日志 | 无 Kubernetes API RBAC | `/proc` hostPath、hostPID、建议 capabilities | 能发现可疑进程，但容器归属可能依赖 CRI socket。 |
| 扫描 + Pod/Namespace 归属 | 无 Kubernetes API RBAC | 上述权限 + CRI socket | 告警中能带出 Pod、Namespace、container ID。 |
| 扫描 + Lark 告警 | 无 Kubernetes API RBAC | 上述权限 + webhook 网络出站 | 能发送告警。 |
| 扫描 + Namespace 自动打标 | `namespaces get/update` | 上述权限 + API Server 网络 | 能在命中的 Namespace 上写入配置的标签。 |
| 完整能力 | `namespaces get/update` | DaemonSet、hostPID、`/proc` hostPath、CRI socket、`SYS_PTRACE`、`DAC_READ_SEARCH`、准入策略允许 | 完成扫描、容器归属、告警、Namespace 打标和 metrics 暴露。 |

## 当前清单状态

当前 `procscan/deploy/manifests` 和 Helm Chart 中的 ProcScan 配置与上述完整能力基本一致：

- 已配置 `ClusterRole`：`namespaces` 的 `get`、`update`。
- 已配置 `ClusterRoleBinding` 到 ProcScan ServiceAccount。
- 已配置 `hostPID: true`。
- 已只读挂载宿主机 `/proc` 到 `/host/proc`。
- 已挂载 containerd socket 到 `/var/run/containerd/containerd.sock`。
- 已设置 `privileged: false`、`allowPrivilegeEscalation: false`、`readOnlyRootFilesystem: true`。
- 已添加 `SYS_PTRACE` 和 `DAC_READ_SEARCH`，并 drop 其他 capabilities。

需要按集群实际情况确认的点：

- 目标节点是否都使用 `/var/run/containerd/containerd.sock`；否则要调整 CRI socket 挂载。
- ProcScan 命名空间的 Pod Security/SCC/PSP 是否允许 hostPID、hostPath 和新增 capabilities。
- 如果需要扫描控制面节点或有 taint 的节点，DaemonSet 是否配置了对应 tolerations。
- 如果开启 `actions.label.enabled=true`，ServiceAccount token 是否自动挂载，且 `namespaces get/update` RBAC 是否生效。
- 如果开启 Lark/飞书告警或 metrics，NetworkPolicy 是否放通对应流量。
