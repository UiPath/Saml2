# Azure DevOps Pipeline for Saml2 Library

This document describes the Azure DevOps pipeline configuration for the UiPath Saml2 library fork.

## Overview

The pipeline automates the build, test, and publishing process for the two main NuGet packages:
- `UiPath.Sustainsys.Saml2`
- `UiPath.Sustainsys.Saml2.AspNetCore2`

## Pipeline Stages

### 1. Build and Test Stage
- **Triggers**: Runs on all PRs and pushes to feature/bugfix branches and v2 branch
- **Actions**:
  - Restores NuGet packages
  - Builds the entire solution in Release configuration
  - Runs all unit tests (AspNetCore2.Tests and Tests.NETCore)
  - Publishes test results and code coverage

### 2. Package Stage
- **Triggers**: Runs after successful build/test stage
- **Actions**:
  - Creates NuGet packages for both main projects
  - Uses semantic versioning (2.9.x format)
  - Adds pre-release tags for non-v2 branches
  - Publishes packages as pipeline artifacts

### 3. Publish Stage
- **Triggers**: Only runs when building the `v2` branch after successful packaging
- **Actions**:
  - Deploys to production NuGet environment
  - Pushes packages to the UiPath internal NuGet feed

## Versioning Strategy

- **Major Version**: 2 (fixed)
- **Minor Version**: 9 (fixed)
- **Patch Version**: Auto-incremented counter
- **Pre-release**: Non-v2 branches get `-alpha{BuildId}` suffix

Examples:
- v2 branch: `2.9.15`
- feature branch: `2.9.15-alpha20231126.1`

## Configuration Requirements

Before using this pipeline, ensure the following are configured in your Azure DevOps project:

### Service Connections
1. **NuGet Service Connection**: Configure connection to your UiPath NuGet feed
   - Name should match `publishVstsFeed` value in pipeline
   - Requires appropriate permissions to push packages

### Environments
1. **nuget-production**: Create an environment for production NuGet deployments
   - Add approval gates if required
   - Configure appropriate security permissions

### Variable Groups (Optional)
Consider creating variable groups for:
- NuGet feed URLs
- Package version overrides
- Environment-specific configurations

## Pipeline Triggers

### Continuous Integration (CI)
```yaml
trigger:
  branches:
    include:
      - v2
      - feature/*
      - bugfix/*
  paths:
    exclude:
      - docs/*
      - README.md
      - LICENSE
      - SECURITY.md
```

### Pull Request (PR)
```yaml
pr:
  branches:
    include:
      - v2
  paths:
    exclude:
      - docs/*
      - README.md
      - LICENSE
      - SECURITY.md
```

## Customization

### Changing NuGet Feed
Update the `publishVstsFeed` value in both NuGetCommand@2 tasks:
```yaml
publishVstsFeed: 'your-feed-name'  # Replace with your actual feed name
```

### Adding More Test Projects
Add additional `DotNetCoreCLI@2` test tasks in the Build stage:
```yaml
- task: DotNetCoreCLI@2
  displayName: 'Run Tests - YourTestProject'
  inputs:
    command: 'test'
    projects: 'Tests/YourTestProject/YourTestProject.csproj'
    arguments: '--configuration $(buildConfiguration) --no-build --logger trx --collect:"XPlat Code Coverage"'
    publishTestResults: true
```

### Modifying Version Strategy
Update the variables section to change versioning:
```yaml
variables:
  majorVersion: 2
  minorVersion: 9
  patchVersion: $[counter(variables['minorVersion'], 0)]
```

## Manual Package Creation (Legacy)

The pipeline replaces the manual process described in the screenshot:
1. ~~Manual project settings update~~
2. ~~`dotnet pack --configuration Release`~~
3. ~~`nuget.exe push` commands~~

All these steps are now automated through the pipeline.

## Troubleshooting

### Build Failures
- Check that all project references are correctly configured
- Ensure NuGet package sources are accessible
- Verify .NET SDK version compatibility

### Test Failures
- Review test output in the pipeline logs
- Check that test certificates and configuration files are included
- Ensure test dependencies are properly restored

### Publishing Failures
- Verify NuGet service connection permissions
- Check that package versions don't conflict with existing packages
- Ensure the target feed exists and is accessible

### Package Version Issues
- Check counter variable configuration
- Verify branch name detection for pre-release tagging
- Review version variable calculations in pipeline logs

## Security Considerations

- NuGet API keys are stored in Azure DevOps service connections (encrypted)
- Production deployments require environment approval (configurable)
- Pipeline only publishes from the `v2` branch to prevent accidental releases
- Sensitive configuration files are excluded from trigger paths

## Monitoring

Monitor pipeline execution through:
- Azure DevOps pipeline runs dashboard
- Build/test result trends
- Package download statistics from NuGet feed
- Environment deployment history
