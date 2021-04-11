---
title: Writing a Kubernetes Admission Controller
author: Felipe
layout: post
---
With the deprecation of [PSP](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/) on Kubernetes v1.21, we will have to migrate to other methods to control the resource permissions in a cluster.

One case that I wanted to handle was running an untrusted job in a cluster, to help review student’s homework and leveraging kubernetes for resource allocation and security. Here we will explore how to develop a new admission controller, that will verify the fields of new jobs on a given namespace are secure enough to run untrusted code in a safe way.


# Recommended policy enforcement applications
If you want to start defining policies for a production cluster, you will probably want to use a ready to use application, which have predefined policies, and setup custom policies easily by using custom resources. Some of them are:

- [Kyverno](https://github.com/kyverno/kyverno)
- [OPA/Gatekeeper](https://github.com/open-policy-agent/gatekeeper)
- [k-rail](https://github.com/cruise-automation/k-rail)

# Cluster requirements
The api-server must have the plugin **ValidatingAdmissionWebhook** enabled (If you want to modify the resources, you also need **MutatingAdmissionWebhook**). Note that these plugins are disabled by default in a kind cluster.

# Application goal
In our example, we will write a validating admission webhook (So we will not modify the resource) that will check new jobs created in a namespace, verifying as many security options of the pod as we can (running as non-root, using gvisor as sandbox, and many others). The target container image that we are targeting is an untrusted job that can be potentially malicious.

# Writing the admission controller
Our admission controller will be written in **Go**, but you can use any language you know as the api use normal https json requests.

I will be trimming some of the code to make it more readable. The full source code can be found at [https://github.com/fdns/simple-admission](https://github.com/fdns/simple-admission)

## Listening to admission requests
First, we will need to create a HTTPS listener (TLS is mandatory). You can use any http path to serve the requests, but you must update the manifest afterwards with the correct location when we define the ValidatingAdmissionWebhook.
```go
func main() {
    // ...
    certs, err := tls.LoadX509KeyPair(certFile, keyFile)

    server := &http.Server{
        Addr: fmt.Sprintf(":%v", port),
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{certs},
        },
    }

    // Define server  handler
    handler := AdmissionHandler{
        RuntimeClass: runtimeClass,
    }
    mux := http.NewServeMux()
    mux.HandleFunc("/validate", handler.handler)
    server.Handler = mux

    go func() {
        log.Printf("Listening on port %v", port)
        if err := server.ListenAndServeTLS("", ""); err != nil {
            log.Printf("Failed to listen and serve webhook server: %v", err)
            os.Exit(1)
        }
    }()

    // Listen to the shutdown signal
    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
    <-signalChan

    log.Printf("Shutting down webserver")
    server.Shutdown(context.Background())
}
```

## Handling admission request
When receiving the request, you must load the body as an AdmissionReview object. This object contains all the information of the objects that is being created.

```go
import (
    admission "k8s.io/api/admission/v1beta1"
    batchv1 "k8s.io/api/batch/v1"
    k8meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (handler *AdmissionHandler) handler(w http.ResponseWriter, r *http.Request) {
    var body []byte
    if r.Body != nil {
        data, err := ioutil.ReadAll(r.Body)
        if err == nil {
            body = data
        } else {
            log.Printf("Error %v", err)
            http.Error(w, "Error reading body", http.StatusBadRequest)
            return
        }
    }

    request := admission.AdmissionReview{}
    if err := json.Unmarshal(body, &request); err != nil {
        log.Printf("Error parsing body %v", err)
        http.Error(w, "Error parsing body", http.StatusBadRequest)
        return
    }

    result, err := checkRequest(request.Request, handler)
    // ...
}
```

## Validating the request
In the **checkRequest** function, we will check if we can handle the resource, verifying the resource group, kind, operation and namespace.
```go
func checkRequest(request *admission.AdmissionRequest, handler *AdmissionHandler) (bool, error) {
    if request.RequestKind.Group != "batch" || request.RequestKind.Kind != "Job" || request.Operation != "CREATE" {
        log.Printf("Skipped resource [%v,%v,%v], check rules to exclude this resource", request.RequestKind.Group, request.RequestKind.Kind, request.Operation)
        return true, nil
    }
    // ...
}
```

The resource body (In our case, a Job) must un unmarshal again before we can verify the parameters.
```go
    var job *batchv1.Job
    err := json.Unmarshal(request.Object.Raw, &job)
    if err != nil {
        log.Printf("Error parsing job %v", err)
        return true, nil
    }

    return checkJob(job, handler)
```

## Checking the resource
On the **checkJob**, we will have full access to the resource parameters. Most of the parameters that are not defined will be **nil**, so you must verify that the parameters is defined before getting its value.

I will copy some of the rules as an example, and the full list that I defined can be found [here](https://github.com/fdns/simple-admission/blob/e09fb1676442122e8518547f20dedf12332ea061/serve.go#L97).

```go
func checkJob(request *batchv1.Job, handler *AdmissionHandler) (bool, error) {
    if request.Spec.ActiveDeadlineSeconds == nil || *request.Spec.ActiveDeadlineSeconds == 0 {
        return false, fmt.Errorf("activeDeadlineSeconds must be set")
    }

    spec := request.Spec.Template.Spec
    if spec.RuntimeClassName == nil || *spec.RuntimeClassName != handler.RuntimeClass {
        return false, fmt.Errorf("wrong RuntimeClass %v is set for job %v, must be %v", spec.RuntimeClassName, request.Name, handler.RuntimeClass)
    }

    if spec.HostNetwork != false {
        return false, fmt.Errorf("HostNetwork must not be set")
    }

    if spec.SecurityContext != nil && len(spec.SecurityContext.Sysctls) > 0 {
        return false, fmt.Errorf("Sysctls must be empty")
    }

    // ...

    for _, container := range spec.Containers {
        if container.SecurityContext == nil {
            return false, fmt.Errorf("SecurityContext must be set for the container")
        }
        context := *container.SecurityContext

        if context.RunAsNonRoot == nil || *context.RunAsNonRoot != true {
            return false, fmt.Errorf("RunAsNonRoot must be set per container")
        }

        // ...
    }
    return true, nil
}
```

## Returning to the api-server
After doing all the validations, you must return an **AdmissionResponse** object that is json encoded. In this object we will define if the objects is allowed or not in our cluster. We can also append a message that will be displayed when the resource is not allowed, so the developer can fix the resource according to the conditions you define.

```go
	result, err := checkRequest(request.Request, handler)
	response := admission.AdmissionResponse{
		UID:     request.Request.UID,
		Allowed: result,
	}
	if err != nil {
		response.Result = &k8meta.Status{
			Message: fmt.Sprintf("%v", err),
			Reason:  k8meta.StatusReasonUnauthorized,
		}
	}

	outReview := admission.AdmissionReview{
		TypeMeta: request.TypeMeta,
		Request:  request.Request,
		Response: &response,
	}
	json, err := json.Marshal(outReview)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response %v", err), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(json); err != nil {
			log.Printf("Error writing response %v", err)
			http.Error(w, fmt.Sprintf("Error writing response: %v", err), http.StatusInternalServerError)
		}
	}
```

## Building our project
As this is a standard go project, you can use a very simple Dockerfile to create the image. This image can be built by running *docker build . --tag fdns/simple-admission:latest* (You can change the tag to the one you like).

```
FROM golang:1.16.2 as builder

WORKDIR $GOPATH/src/github.com/fdns/simple-admission
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /go/bin/simple-admission

FROM scratch
COPY --from=builder /go/bin/simple-admission /go/bin/simple-admission
ENTRYPOINT ["/go/bin/simple-admission"]
```

The only thing left is uploading it to our cluster.

# Uploading controller to a kubernetes cluster

## Create TLS certificates
As the webhook require the use of HTTPS to work, we can create our own CA and certificate for the controller. The CA keys can be dropped as soon as we sign the client certificate, as the CA bundle is included in the ValidatingAdmissionWebhook object.

As the requests will come from a service object, you will want to define as altnames in the certificate all the variations to call the services. In the configuration, this will look as something like the following.
```
[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.${namespace}
DNS.3 = ${service}.${namespace}.svc
```

To stop copying so much code, you can find a simple script to generate the certificate at [https://github.com/fdns/simple-admission/blob/master/generate_certs.sh](https://github.com/fdns/simple-admission/blob/master/generate_certs.sh), which we will call with the service name and namespace of our admission controller (For example, *./generate_certs.sh simple-admission default*).

The generated certificates must be mounted as a secret, as we will need to mount them in our application (save the **ca.pem** file as we will need it later).
```yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: admission-certs
  namespace: default
data:
  server-key.pem: $(cat certs/server-key.pem | base64 | tr -d '\n')
  server.pem: $(cat certs/server.crt | base64 | tr -d '\n')
```

## Creating the service and webhook
You can create the deployment and services the same way as any other deployment in your cluster. Here it is recommended to increase the replica count to increase the availability.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: simple-admission
  name: simple-admission
spec:
  replicas: 1
  selector:
    matchLabels:
      app: simple-admission
  strategy: {}
  template:
    metadata:
      labels:
        app: simple-admission
    spec:
      containers:
      - name: simple-admission
        image: fdns/simple-admission:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: admission-certs
          mountPath: /certs
          readOnly: true
      volumes:
      - name: admission-certs
        secret:
          secretName: admission-certs
---
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: simple-admission
  name: simple-admission
spec:
  ports:
  - name: 443-8443
    port: 443
    protocol: TCP
    targetPort: 8443
  selector:
    app: simple-admission
  type: ClusterIP
```

## Creating the ValidatingAdmissionWebhook
Finally, we will create the **ValidatingAdmissionWebhook**. We can define multiple webhooks, where in each one we must tell kubernetes the service, path and CA to send the request to the admission controller. For each one we can define the rules to filter the requests that are sent to our controller, where in this case we will filter for **jobs** resources in namespaces **labeled** with the name default (the namespace **MUST** be labeled in our example).

In case you want to audit your webook before applying it to your cluster, you can change the failurePolicy from **Fail** to **Ignore**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
 name: simple-admission.default.cluster.local
 namespace: default
webhooks:
- name: simple-admission.default.cluster.local
  clientConfig:
    service:
      name: simple-admission
      namespace: default
      path: "/validate"
    caBundle: $(cat certs/ca.pem | base64 | tr -d '\n')
  rules:
  - apiGroups: ["batch"]
    apiVersions: ["v1"]
    resources: ["jobs"]
    operations: ["CREATE"]
    scope: "*"
  namespaceSelector:
    matchExpressions:
    - key: name
      operator: In
      values: ["default"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Fail
```

## Testing our admission controller
To the newly applied admission controller, you can simply try to create a basic job running *kubectl create job test --image busybox*, which in our case will output the following message:
```
error: failed to create job: admission webhook "simple-admission.default.cluster.local" denied the request: activeDeadlineSeconds must be set
```

# Conclusions
Creating an admission controller is not difficult, but making sure all the parameters to make your containers secure is a difficult task, as not all fields are generally known, and new fields must be taken into account when kubernetes release a new version.

When creating a new admission controller, you should try to target a single problem, like image verification or single fields of the resources like runtimeClass over your cluster. In case you need more complex rules, the use of the already available admission controllers is recommended, as you can define the rules in your own CRD and allow you to iterate faster (some of them have audit mode so you can check your cluster before enforcing a rule).
