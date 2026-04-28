## Usage

[Helm](https://helm.sh) must be installed to use the charts.  Please refer to
Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:
```sh
  helm repo add rauthy-controller https://strange-journey.github.io/rauthy-controller
```

If you had already added this repo earlier, run `helm repo update` to retrieve
the latest versions of the packages.  You can then run `helm search repo
rauthy-controller` to see the charts.

## Installation

**1. Install the CRDs** (included in a separate chart):

```sh
helm install \
    rauthy-controller-crds rauthy-controller-crds \
    --repo https://strange-journey.github.io/rauthy-controller \
    --version 0.1.0
```

**2. Create a Secret** with your Rauthy credentials:

```sh
kubectl create secret generic rauthy-api-secret \
    --namespace rauthy \
    --from-literal=RAUTHY_URL='https://rauthy.example.com' \
    --from-literal=RAUTHY_API_KEY='example_key$Ab1C2d3E4f5G6h7I8j9K0lMnoPqRsTuVwXyZ1234567890'
```
The Rauthy API key must be configured with at least **CRUD access to Clients and Secrets**.

**3. Install the controller chart**, referencing the secret:

```sh
helm install \
    rauthy-controller rauthy-controller \
    --repo https://strange-journey.github.io/rauthy-controller \
    --version 0.1.0 \
    --namespace rauthy --create-namespace \
    --set rauthy.existingSecret=rauthy-api-secret
```

See [values.yaml](https://github.com/strange-journey/rauthy-controller/blob/main/charts/rauthy-controller/values.yaml) for all available configuration options.
