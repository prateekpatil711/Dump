# Integration of CSKM with CKEY Using Vault Injector

## Overview

Integrating CSKM with CKEY enhances security by dynamically managing secrets and securely injecting them into applications. Using the Vault injector, an open-source Vault chart, secrets are injected directly into Kubernetes pods, ensuring that sensitive information such as database credentials or API keys is handled securely and automatically rotated. This integration significantly improves the overall security posture of the system.

## Steps to Integrate CKEY with CSKM

### Step 1. Installation of CSKM

Ensure CSKM is installed with the Kubernetes authentication method by enabling the `kubernetesAuth` parameter in the `Values.yaml` file. Once installed, exec into the CSKM pod and follow these steps to enable authentication, create secrets, and configure policies.

### Step 2. Retrieve Vault Token and CSKM Service IP

To connect to Vault from the Kubernetes cluster, obtain the Vault token and the CSKM service IP as follows:

#### a. Retrieve the Vault Token
Obtain the Vault token from the secret `my-cskm-cskm-secret` that is generated after installing the CSKM chart:

```bash
export VAULT_TOKEN=$(kubectl -n testcskm get secret my-cskm-cskm-secret -o jsonpath='{.data.token}' | base64 --decode)
```

#### b. Retrieve the CSKM Service IP
Get the Service IP of the CSKM:

```bash
export VAULT_ADDR=$(kubectl get service my-cskm-cskm -n testcskm -o jsonpath='{.spec.clusterIP}')
export VAULT_ADDR=https://$VAULT_ADDR:8200
```

### Step 3. Enable KV-V2 Secrets at the Path `internal`

Users' login credentials are expected to be stored in Vault at the path `internal/database/config` by the apps you launch in the Inject secrets into the pod section. Enabling a key-value secret engine and entering a login and password at the designated path are necessary to generate this secret. To enable the KV-V2 secrets engine at the path `internal`:

```bash
curl -k --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type": "kv-v2"}' $VAULT_ADDR/v1/sys/mounts/internal
```

### Step 4. Create a Secret at Path `internal/database/config`

Create a secret at the path `internal/database/config` with the following username and password:

```bash
curl -k --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"data": {"username": "db-readonly-username", "password": "db-secret-password"}}' $VAULT_ADDR/v1/internal/data/database/config
```


## Kubernetes and Vault Integration

### Step 5: Create a Configuration File for Kubernetes Authentication

Create a `config.json` file to configure Kubernetes authentication with Vault. This file should contain the following details:

```json
{
  "kubernetes_host": "https://10.254.0.1",
  "kubernetes_ca_cert": "-----BEGIN CERTIFICATE-----\nMIIDcjCCAlqgAwIBAgIIVCCCuc+dREswDQYJKoZIhvcNAQELBQAwUDELMAkGA1UEBhMCQUExCzAJBgNVBAgMAkFBMQswCQYDVQQHDAJBQTELMAkGA1UECgwCQUExCzAJBgNVBAsMAkFBMQ0wCwYDVQQDDARCQ01UMB4XDTI0MDIyNzEwMDkyM1oXDTI2MDUzMDEwMDkyM1owUDELMAkGA1UEBhMCQUExCzAJBgNVBAgMAkFBMQswCQYDVQQHDAJBQTELMAkGA1UECgwCQUExCzAJBgNVBAsMAkFBMQ0wCwYDVQQDDARCQ01UMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvT/4gp78l3Yf7ZQyg0yiNOD0mAb6P3RH7heY5UBeEhyTkn8/onfkiJ1gVFkgfibJ5RPAgjd8VcLiw7R9k7wNV/r52Wvd2xE9OjWMe0JMgk/2jKnO6NtvKzeqA7nb82k5u0bxdqLEdTxtn9ZZ7VTyFUZlzUzGOdHLwsumLeoHwJIXFvgkyioa81OibddKnC0Um4UexEDYohqBguhv+Wel+tU6gHzVp9a8Qg86cHTyfBfM9NNXrz5GD8gdTaZA52+BMIucQvxu1Ww/Hxi+oFoY29g+/J9P/5ySYR2eRSaguj48J3qT2+PT5yUNw/DyQRcGuKXjvNxJegwYubQlFUS1vQIDAQABo1AwTjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTPOXwJ+LO+tILOBbnBojiTpoL04zAfBgNVHSMEGDAWgBTPOXwJ+LO+tILOBbnBojiTpoL04zANBgkqhkiG9w0BAQsFAAOCAQEAd6ACExQltSFV4dGZ7AiomKUOSuAE/rP/Tgm5NnGfnSsk07urFlINUyDNQEJ8fB2/YW2fHHdK+x5UU0wh4GQbGChAyR5K6IUqphGKUsmeTvJq61rRiCUykdonT8dEIGtT+GgtmBWCdM9WS5bEZ4oY/S3QrgT8jHkzUXKGOGVOfpXLE7kBxkvhh5wVK/7ArmrNmNsD35FKbKr6Th/xwHlBIRmb1d0N13fFLk6Hwh5wUmOt/FhwjW95kkQeske1icp9KB2v7O8O9OGCxctiPgQoTBAwojaVEw7z460POQahb7m2pWb+71tWFaqvkRXGO/TNrAOIYwb27y9XhgNqU7N2ug==\n-----END CERTIFICATE-----",
  "disable_local_ca_jwt": false
}
```

This file defines the Kubernetes host and the certificate required for authentication. It also includes an option to disable the local CA JWT if necessary.

### Step 6: Apply the Configuration and Verify

To apply the configuration, use the following `curl` command to post the `config.json` file to the Vault Kubernetes authentication endpoint:

```sh
curl -k --header "X-Vault-Token:$VAULT_TOKEN" --request POST --data @config.json $VAULT_ADDR/v1/auth/kubernetes/config
```

You can verify the configuration by querying the Kubernetes authentication endpoint:

```sh
curl -k --header "X-Vault-Token:$VAULT_TOKEN" $VAULT_ADDR/v1/auth/kubernetes/config | jq
```

### Step 7: Define a Policy for Accessing Secrets

Create a policy named `int-ckey` that grants read access to secrets located at the path `internal/data/database/config`. The policy is defined in a JSON file as follows:

```json
{ "policy": "path \"internal/data/database/config\" {\n capabilities = [\"read\"]\n}\n" }
```

Apply the policy using the following `curl` command:

```sh
curl -k --header "X-Vault-Token: $VAULT_TOKEN"  --request PUT  --data-binary @policy.json $VAULT_ADDR/v1/sys/policy/int-ckey
```

### Step 8: Create a Kubernetes Authentication Role

Next, create a Kubernetes authentication role named `int-ckey`. This role binds a specific service account used by the CKEY StatefulSet to the authentication policy. The role configuration is defined as follows:

```json
{
  "bound_service_account_names": "my-ckey-ckey-stateful-sa",
  "bound_service_account_namespaces": "testcskm",
  "policies": "keycloak-policy",
  "ttl": "24h"
}
```

To apply the role, use the following `curl` command:

```sh
curl -k --request POST  --header "X-Vault-Token: $VAULT_TOKEN "  --data @role-data.json  $VAULT_ADDR/v1/auth/kubernetes/role/int-ckey
```

This role binds the service account of the CKEY StatefulSet, allowing its service account token to be used for Kubernetes authentication as an intermediate step.

### Step 9: Install the Vault Injector

To install the Vault injector, use the open-source Vault Helm chart. After unzipping the chart, configure the parameters in the `values.yaml` file as follows:

```yaml
global:
    externalVaultAddr: "https://my-cskm-cskm.testcskm.svc.cluster.local:8200"
injector:
    enabled: true
    image:
        repository: "registry1-docker-io.repo.cci.nokia.net/hashicorp/vault-k8s"
        tag: "1.4.1"
        pullPolicy: IfNotPresent
    agentImage:
        repository: "registry1-docker-io.repo.cci.nokia.net/hashicorp/vault"
        tag: "1.16.1"
    securityContext:
        pod:
            runAsUser: 1000
            runAsGroup: 1000
            fsGroup: 1000
        container:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
```

Install the Vault Helm chart using Helm:

```sh
helm3 install my-vault vault-helm-main -n testcskm
```

Verify the installation by checking the status of the pods:

```sh
kubectl get pods -n testcskm
```

### Step 10: Configure TLS for CSKM

Since CSKM operates in default TLS mode with certManager enabled, create a Kubernetes secret containing the `ca.crt`, `tls.crt`, and `tls.key` files. These files are available in the `/opt/Vault/tls` directory inside the CSKM pod. To create the secret, use the following command:

```sh
kubectl create secret generic cskm-tls-secret -n testcskm --from-file=ca.crt=ca.crt --from-file=tls.crt=tls.crt --from-file=tls.key=tls.key
```



### Step 11: Installation of CKEY

Install CKEY with the default configuration, ensuring the `automountServiceAccountToken` parameter is enabled in the `Values.yaml` file. This will automatically mount the service account token necessary for Kubernetes authentication.

![image](https://github.com/user-attachments/assets/3f9a9f39-feca-41e6-b633-fcc79fc01415)

### Step 12: Patching the CKEY StatefulSet to inject Vault Injector

After configuring your environment, the next step is to patch the CKEY StatefulSet to include the Vault injector container. This will enable automatic secrets injection from HashiCorp Vault into the application. Below are the steps to accomplish this:

#### 1. Create a Patch File
Begin by creating a patch file named `patch-chart.yaml` with the following content:

```yaml
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: 'true'
        vault.hashicorp.com/role: 'int-ckey'
        vault.hashicorp.com/agent-inject-secret-database-config.txt: 'internal/data/database/config'
        vault.hashicorp.com/ca-cert: '/vault/tls/ca.crt'
        vault.hashicorp.com/tls-secret: 'cskm-tls-secret'
```

This patch adds annotations to the StatefulSet’s Pod template, enabling the Vault agent injector to inject secrets into the CKEY application.

- `vault.hashicorp.com/agent-inject` : configures whether injection is explicitly enabled or disabled for a pod. This should be set to a true or false value. Defaults to false.
- `vault.hashicorp.com/role` : Specifies the Vault role to be used by the injector.
- `vault.hashicorp.com/agent-inject-secret-database-config.txt` : Configures Vault Agent to retrieve the secrets from Vault required by the container. The name of the secret is any unique string after **vault.hashicorp.com/agent-inject-secret-**, such as **vault.hashicorp.com/agent-inject-secret-foobar**. The value is the path in Vault where the secret is located.
- `vault.hashicorp.com/ca-cert` : path of the CA certificate used to verify Vault's TLS. This can also be set as the default for all injected Agents via the **AGENT_INJECT_VAULT_CACERT_BYTES** environment variable which takes a PEM-encoded certificate or bundle.
- `vault.hashicorp.com/tls-secret` : name of the Kubernetes secret containing TLS Client and CA certificates and keys. This is mounted to /vault/tls.


#### 2. Apply the Patch to the StatefulSet

Use the following command to apply the patch to the CKEY StatefulSet:

```bash
kubectl patch sts my-ckey-ckey -n testcskm --patch "$(cat patch-chart.yaml)"
```

This command applies the patch defined in `patch-chart.yaml` to the StatefulSet named `my-ckey-ckey` in the `testcskm` namespace.

