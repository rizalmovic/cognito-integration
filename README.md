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

To authenticate we going to use `InitiateAuth` method from `AWS.CognitoIdentityServiceProvider` class. You can find the parameters need for the method on [AWS Cognito documentation](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html#initiateAuth-property)

```typescript
...
  authenticate(username: string, password: string): Promise<Object> {
    const params = {
      AuthFlow: AUTH_TYPE.auth,
      ClientId: this.AppClientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH: this.generateSecretHash(username),
      },
    };

    return new Promise((resolve, reject) => {
      this.cognito.initiateAuth(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Sign Up

To sign up we can use `signUp` method from `AWS.CognitoIdentityServiceProvider` class. We also need to generate `SecretHash` by generating secret hash. You can found the the implementation of generating hash on `generateSecretHash` method on `Cognito` class.

```typescript
...
  generateSecretHash(username: string): string {
    return crypto
      .createHmac('SHA256', this.SECRET)
      .update(username + this.AppClientId)
      .digest('base64');
  }
...
```

Parameters for signup are documented on [AWS Cognito documentation](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html#signUp-property)

```typescript
...
  signUp(
    username: string,
    password: string,
    attributes: {Name: string; Value: string}[],
  ) {
    const params = {
      ClientId: this.AppClientId,
      Username: username,
      Password: password,
      SecretHash: this.generateSecretHash(username),
      UserAttributes: attributes,
    };

    return new Promise<SignUpResponse>((resolve, reject) => {
      this.cognito.signUp(params).send((err, data) => {
        if (err) {
          reject(err);
        } else resolve(data);
      });
    });
  }
...
```

#### Signup confirmation

To confirm sign up we're going to use method `confirmSignUp` from `AWS.CognitoIdentityServiceProvider` class. Parameters for signup are documented on [AWS Cognito documentation](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html#confirmSignUp-property)

```typescript
...
  confirmSignUp(username: string, confirmationCode: string) {
    const params = {
      ClientId: this.AppClientId,
      ConfirmationCode: confirmationCode,
      Username: username,
      SecretHash: this.generateSecretHash(username),
    };

    return new Promise((resolve, reject) => {
      this.cognito.confirmSignUp(params).send((err, data) => {
        if (err) {
          reject(err);
        } else resolve(data);
      });
    });
  }
...
```

#### Resend confirmation code

```typescript
...
  resendConfirmationCode(username: string) {
    const params = {
      ClientId: this.AppClientId,
      Username: username,
      SecretHash: this.generateSecretHash(username),
    };

    return new Promise<
      | AWS.AWSError
      | AWS.CognitoIdentityServiceProvider.ResendConfirmationCodeResponse
    >((resolve, reject) => {
      this.cognito.resendConfirmationCode(params).send((err, data) => {
        if (err) {
          reject(err);
        } else resolve(data);
      });
    });
  }
...
```

#### Add user role / group

```typescript
...
  adminAddUserToGroup(username: string) {
    const params = {
      GroupName: this.GROUP_NAME.user /* required */,
      UserPoolId: this.UserPoolId /* required */,
      Username: username /* required */,
    };

    return new Promise((resolve, reject) => {
      this.cognito.adminAddUserToGroup(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Remove user from role / group

```typescript
...
  adminRemoveUserFromGroup(username: string) {
    const params = {
      GroupName: this.GROUP_NAME.user /* required */,
      UserPoolId: this.UserPoolId /* required */,
      Username: username /* required */,
    };

    return new Promise((resolve, reject) => {
      this.cognito.adminRemoveUserFromGroup(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Forgot password

```typescript
...
  forgotPassword(username: string) {
    const params = {
      ClientId: this.AppClientId,
      Username: username,
      SecretHash: this.generateSecretHash(username),
    };

    return new Promise((resolve, reject) => {
      this.cognito.forgotPassword(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Confirm forgot password

```typescript
...
  confirmForgotPassword(
    username: string,
    password: string,
    confirmationCode: string,
  ) {
    const params = {
      ClientId: this.AppClientId,
      Username: username,
      Password: password,
      ConfirmationCode: confirmationCode,
      SecretHash: this.generateSecretHash(username),
    };

    return new Promise<
      | AWS.AWSError
      | AWS.CognitoIdentityServiceProvider.ConfirmForgotPasswordResponse
    >((resolve, reject) => {
      this.cognito.confirmForgotPassword(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Change Password

```typescript
...
  changePassword(
    token: string,
    previousPassword: string,
    proposedPassword: string,
  ) {
    const params = {
      AccessToken: token,
      PreviousPassword: previousPassword,
      ProposedPassword: proposedPassword,
    };

    return new Promise<
      AWS.AWSError | AWS.CognitoIdentityServiceProvider.ChangePasswordResponse
    >((resolve, reject) => {
      this.cognito.changePassword(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Sign Out

```typescript
...
  signOut(token: string) {
    const params = {
      AccessToken: token,
    };

    return new Promise<
      AWS.AWSError | AWS.CognitoIdentityServiceProvider.GlobalSignOutResponse
    >((resolve, reject) => {
      this.cognito.globalSignOut(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Responds to Auth challenge

```typescript
...
  respondToAuthChallenge(
    challengeName: string,
    challengeResponse?: Object,
    session?: string,
  ) {
    let params = {
      ChallengeName: challengeName,
      ClientId: this.AppClientId,
    };

    if (challengeResponse) {
      params = Object.assign(params, {
        ChallengeResponses: challengeResponse,
      });
    }

    if (session) {
      params = Object.assign(params, {
        Session: session,
      });
    }

    return new Promise<
      | AWS.AWSError
      | AWS.CognitoIdentityServiceProvider.RespondToAuthChallengeResponse
    >((resolve, reject) => {
      this.cognito.respondToAuthChallenge(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
...
```

#### Get Certificate

```typescript
...
  async getCertificate() {
    const url = `https://cognito-idp.${this.CognitoConfig.region}.amazonaws.com/${this.UserPoolId}/.well-known/jwks.json`;
    const result = await Axios.get(url)
      .then(res => {
        if (res.status === 200) {
          // eslint-disable-next-line
          const pems: any = {};
          const keys = res.data['keys'];

          for (const key of keys) {
            pems[key.kid] = jwkToPem(key);
          }

          return pems;
        } else {
          throw new Error('Error, Unable to download JWKs');
        }
      })
      .catch(err => {
        throw new Error(err);
      });
    return result;
  }
...
```

#### Verify Token

```typescript
...
  verifyToken(token: string, pems: any) {
    // eslint-disable-next-line
    const decodedJwt: any = jwt.decode(token, {complete: true});

    if (!decodedJwt) throw new Error('Invalid JWT Token');
    const kid = decodedJwt.header.kid;
    const pem = pems[kid];

    if (!pem) throw new Error('Invalid Token');

    return new Promise((resolve, reject) => {
      // eslint-disable-next-line
      jwt.verify(token, pem, (err: any, payload: any) => {
        if (err) reject(err);
        else resolve(payload);
      });
    });
  }
...
```

### Configure Message customizations using Trigger and AWS Lamda

Describe the steps that need to be done to customize or process message.

## References

- [AWS Cognito Documentation](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityServiceProvider.html)
