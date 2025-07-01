# azure-apim-policy-toolkit

## Generate policies

```bash
dotnet tool install Azure.ApiManagement.PolicyToolkit.Compiling
```

```bash
dotnet azure-apim-policy-compiler --s ./MyCorp.Apis.Policies --o ./output --format true
```

## Unit test policies

```bash
dotnet test
```