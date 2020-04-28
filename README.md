# Cognito Implementation on Node.js Application

This repository will talk about how to implement AWS Cognito into your nodejs application.
For the source code, you could check on the `cognito.ts` file.

## Requirements

- `aws-sdk`
- `jasonwebtoken`
- `jwk-to-pem`

## Steps

- Create User Pool
- Install all necessary libraries (`aws-sdk`, `jasonwebtoken`, `jwk-to-pem`)
- Create Cognito library as a wrapper to interact with AWS Cognito API via `aws-sdk` | `Optional`
- Configure Message customizations using Trigger and AWS Lamda | `Optional`

### Create User Pool

Describe the steps that need to setup a new user pool.

### Install libraries

Describe how to install all libraries needed for the integration

### Create Cognito library

Before create the wrapper, there are several keys that we're going to need to interact AWS via CLI, SDK & API Access. Below are the keys that we need :

- AWS Access Key - AWS IAM
- AWS Secret Access Key - AWS IAM
- AWS Region
- AWS Cognito Pool ID
- AWS Cognito Secret
- AWS Cognito App Client ID

#### Initiate CognitoServiceProvider

To use `aws-sdk`, we need to update configuration of AWS by using `AWS.config.update(config)`. The `config` consist of `accessKeyId`, `secretAccessKey` and `region`. After that we could initiate `CognitoIdentityServiceProvider`.

```typescript
...
 constructor(config?: Object) {
    if (config) {
      this.CognitoConfig = Object.assign(this.CognitoConfig, config);
    }

    AWS.config.update(this.CognitoConfig);
    this.cognito = new AWS.CognitoIdentityServiceProvider();
  }
...
```

#### Authenticate

To authenticate we going to use `InitiateAuth` method from `AWS.CognitoIdentityServiceProvider` class.

### Configure Message customizations using Trigger and AWS Lamda

Describe the steps that need to be done to customize or process message.

## References

- [AWS Cognito Documentation](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html)
