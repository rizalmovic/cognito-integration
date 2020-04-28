import AWS from 'aws-sdk';
import {SignUpResponse} from 'aws-sdk/clients/cognitoidentityserviceprovider';
import Axios from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';

export enum AUTH_TYPE {
  auth = 'USER_PASSWORD_AUTH',
  refreshToken = 'REFRESH_TOKEN',
}

export enum CHALLENGE_NAME {
  SMS_MFA = 'SMS_MFA',
  SOFTWARE_TOKEN_MFA = 'SOFTWARE_TOKEN_MFA',
  SELECT_MFA_TYPE = 'SELECT_MFA_TYPE',
  MFA_SETUP = 'MFA_SETUP',
  PASSWORD_VERIFIER = 'PASSWORD_VERIFIER',
  CUSTOM_CHALLENGE = 'CUSTOM_CHALLENGE',
  DEVICE_SRP_AUTH = 'DEVICE_SRP_AUTH',
  DEVICE_PASSWORD_VERIFIER = 'DEVICE_PASSWORD_VERIFIER',
  ADMIN_NO_SRP_AUTH = 'ADMIN_NO_SRP_AUTH',
  NEW_PASSWORD_REQUIRED = 'NEW_PASSWORD_REQUIRED',
}

export class Cognito {
  cognito: AWS.CognitoIdentityServiceProvider;
  CognitoConfig = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
    region: process.env.AWS_REGION ?? '',
  };
  AppClientId = process.env.AWS_COGNITO_APP_CLIENTID ?? '';
  SECRET = process.env.AWS_COGNITO_SECRET ?? '';
  UserPoolId = process.env.AWS_USER_POOL_ID ?? '';
  constructor(config?: Object) {
    if (config) {
      this.CognitoConfig = Object.assign(this.CognitoConfig, config);
    }

    AWS.config.update(this.CognitoConfig);
    this.cognito = new AWS.CognitoIdentityServiceProvider();
  }

  GROUP_NAME = {
    administrator: 'administrator',
    healthcare: 'healthcare',
    user: 'user',
  };

  generateSecretHash(username: string): string {
    return crypto
      .createHmac('SHA256', this.SECRET)
      .update(username + this.AppClientId)
      .digest('base64');
  }

  /**
   * Authenticate
   * @param {string} username string
   * @param {string} password string
   * @returns Promise
   */
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

  /**
   * Sign Up
   * @param {string} username
   * @param {string} password
   * @param {Object[]}attributes
   */
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

  /**
   *
   * Confirm Sign Up after user get verification code
   * Set to null if the request is successful
   * @param {string} username
   * @param {string} confirmationCode
   * @memberof Cognito
   */
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

  /**
   *
   * Adds the specified user to the specified group.
   * Set to null if the request is successful
   * @param {string} username
   * @memberof Cognito
   */
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

  /**
   *
   * Remove group / role from the specified user.
   * Set to null if the request is successful
   * @param {string} username
   * @memberof Cognito
   */
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

  /**
   *
   * @param username Forgot Password
   * @returns {Promise}
   */
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

  /**
   *
   * @param {string} username
   * @param {string} password
   * @param {string} confirmationCode
   * @returns {Promise<AWS.AWSError|AWS.CognitoIdentityServiceProvider.ConfirmForgotPasswordResponse>}
   */
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

  /**
   *
   * @param {string} username Change Password
   * @return {Promise}
   */
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

  /**
   * Global signout
   * @param {string} token string token key
   */
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

  /**
   * Get user
   * @param {string} token string
   * @return {Promise}
   */
  getUser(token: string) {
    return new Promise<
      AWS.AWSError | AWS.CognitoIdentityServiceProvider.GetUserResponse
    >((resolve, reject) => {
      this.cognito.getUser({AccessToken: token}).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }

  /**
   * Delete a user as an Administrator
   * @param {string} username string
   * @returns {Promise}
   */
  deleteUser(username: string) {
    const params = {
      UserPoolId: this.UserPoolId,
      Username: username,
    };
    return new Promise<AWS.AWSError | Object>((resolve, reject) => {
      this.cognito.adminDeleteUser(params).send((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }

  /**
   *
   * @param {string} challengeName
   * @param {string} challengeResponse
   * @returns {Promise<AWS.AWSError | AWS.CognitoIdentityServiceProvider.RespondToAuthChallengeResponse>}
   */
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

  // eslint-disable-next-line
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

  /**
   *
   *
   * @param {string} username
   * @returns AWS.AWSError | AWS.CognitoIdentityServiceProvider.ResendConfirmationCodeResponse
   * @memberof Cognito
   */
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
}
