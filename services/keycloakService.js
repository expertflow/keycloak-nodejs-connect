let session = require( "express-session" );
let Keycloak = require( "keycloak-connect" );
const fs = require( 'fs' );
const Joi = require( "joi" );
const qrcode = require( "qrcode" );
const speakeasy = require( 'speakeasy' )
const parseXMLString = require( "xml2js" ).parseString;

let requestController = require( "../controller/requestController.js" );
let memory = new session.MemoryStore();

let realmRoles = [];
let previousEvents = []; // Store complete events instead of just IDs
let isFirstRun = true;

const FinesseService = require( "./finesseService" );
const TeamsService = require( "./teamsService" );
const ErrorService = require( './errorService.js' );
const CiscoSyncService = require( './ciscoSyncService.js' );

const finesseService = new FinesseService();
const teamsService = new TeamsService();
const errorService = new ErrorService();
const ciscoSyncService = new CiscoSyncService();

class KeycloakService extends Keycloak {

  constructor ( config ) {

    super( { store: memory }, { ...config } ); //initialising keycloak-connect   //Keycloak = new Keycloak({store: memory}, config);
    this.keycloakConfig = { ...config };

  }

  //Based on the attributes it either authenticate keycloak user or finesse user.
  async authenticateUserViaKeycloak( user_name, user_password = '', realm_name, twoFAConfigs, finesseUrl = '', userRoles = [], finesseToken = '' ) {

    let token = "";

    // If finesseUrl is empty it means normal keycloak auth is required.
    if ( !finesseUrl || finesseUrl == "" ) {
      token = await this.getKeycloakTokenWithIntrospect( user_name, user_password, realm_name, 'CX' );
      let attributesFromToken = token.keycloak_User.attributes

      if ( twoFAConfigs?.is2FAEnabled ) {     // if 2FA is enabled then running the 2FA flow
        const twoFAChannel = twoFAConfigs.channelType;
        const allowedChannels = ['APP', 'RSA', 'SMS', 'EMAIL'];
        if ( !twoFAChannel || !allowedChannels.includes(twoFAChannel) ) {
          return Promise.reject( { status: 400, error_message: 'channelType is empty or invalid in 2FA configuration.' } )
        }

        // token for only sending info related to 2FA
        let tempToken = {
          username: user_name
        };

        // checking if user attributes in keycloak exist or not to confirm 2FA registration
        if ( !attributesFromToken?.is2FARegistered || attributesFromToken.is2FARegistered == 'false' ) {

          // getting admin access token to update the user attributes for RSA & Auht Apps
          const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN );
          const adminToken = adminData.access_token;

          // appending extra information regarding 2FA in response object
          tempToken.is2FARegistered = false
          tempToken.twoFAChannel = twoFAChannel
          tempToken.message = "2FA registration required"

          // handling RSA authenticator scenario exclusively
          if ( twoFAChannel === 'RSA' ) {

            tempToken.is2FARegistered = true;
            tempToken.message = "OTP required.";

            //updating user attributes for RSA MFA
            let newAttributes = {};
            if ( attributesFromToken ) newAttributes = attributesFromToken;
            newAttributes.twoFAChannel = "RSA";
            newAttributes.is2FARegistered = true;

            await this.updateUserAttributes( adminToken, token.keycloak_User.id, newAttributes );
          }

          // if 2FA is required through authenticator app then performing necessary operation in keycloak user attributes
          else if ( twoFAChannel == 'APP' ) {

            // QR Code and Secret Code generation based on username
            const qrSetup = await this.getQRCode( user_name )
            if ( qrSetup ) {

              tempToken.otpSecret = qrSetup.secret
              tempToken.qrImage = qrSetup.image
            }
            else return Promise.reject( { error: 404, error_message: 'Error occurred while generating QR code.' } )

            //updating user attributes for 2FA
            let newAttributes = {}
            if ( attributesFromToken ) newAttributes = attributesFromToken
            newAttributes.tempOTPSecret = qrSetup.secret
            newAttributes.twoFAChannel = 'APP'
            newAttributes.is2FARegistered = false

            // saving the Secret Code into KeyCloak as user attribute to validate the OTP on each login
            await this.updateUserAttributes( adminToken, token.keycloak_User.id, newAttributes )
          }

          // if 2FA is configured via sms/email
          else {
            //updating user attributes for 2FA via sms/email
            let newAttributes = {}
            if ( attributesFromToken ) newAttributes = attributesFromToken
            newAttributes.twoFAChannel = twoFAChannel
            newAttributes.is2FARegistered = false
            newAttributes.channelServiceIdentifier = twoFAConfigs.channelServiceIdentifier
            newAttributes.otpExpiry = twoFAConfigs.otpExpiry
            newAttributes.otpMaxAttempts = twoFAConfigs.otpMaxAttempts

            // saving OTP Manager configs for respective user for subsequent logins 
            await this.updateUserAttributes( adminToken, token.keycloak_User.id, newAttributes )
          }

        } else if ( attributesFromToken.is2FARegistered[ 0 ] == 'true' ) {     // if user has already registered for 2FA
          tempToken.is2FARegistered = true
          tempToken.twoFAChannel = attributesFromToken.twoFAChannel[ 0 ]
          tempToken.message = "OTP required."
          
          let otpManagerSupportedChannels = ["SMS", "EMAIL"]
          if ( otpManagerSupportedChannels.includes(attributesFromToken.twoFAChannel[0]) ) {
            if ( !attributesFromToken.customerChannelIdentifier ) {
              return Promise.reject( {
                error: 404,
                error_message: 'Error occurred while fetching customerChannelIdentifier from user attributes.'
              } )
            }

            twoFAConfigs.customerChannelIdentifier = attributesFromToken.customerChannelIdentifier[0]
            try {
              await this.sendOTPviaOTPManager( user_name, twoFAConfigs )            
            } catch (error) {
              return Promise.reject({
                error_message: 'An error occured while sending OTP via OTP Manager.',
                error_detail: error
              })
            }

            if( attributesFromToken.twoFAChannel[0]=='SMS' )
              tempToken.phoneNumber = attributesFromToken.customerChannelIdentifier[ 0 ]
            else
              tempToken.email = attributesFromToken.customerChannelIdentifier[0]
          }

          // deleting otpSecret from response
          if ( token.keycloak_User.attributes.otpSecret )
            delete token.keycloak_User.attributes.otpSecret
        }
        else {
          return Promise.reject( {
            error: 404,
            error_message: 'Error occurred while verifying user registration for 2FA.'
          } )
        }

        return tempToken;

      }

      // check for password expiration to return a warning/message
      const warningLimit = this.keycloakConfig[ "PASSWORD_EXPIRY_WARNING_LIMIT" ];
      if ( warningLimit > 0 ) {
        try {
          const passwordExpirationCheck = await this.checkPasswordExpiration( user_name );
          if ( passwordExpirationCheck ) {
            token.passwordExpiration = passwordExpirationCheck;
          }
        } catch ( error ) {
          return Promise.reject( error );
        }
      }

      return token;

    } else {

      // Finesse Auth, takes userRole in argument to create user along with role.
      token = await this.authenticateFinesse( user_name, user_password, finesseUrl, userRoles, finesseToken );

      return token;

    }
  }

  async getAccessToken( user_name, user_password ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          username: user_name,
          password: user_password,
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE,
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Token Generation Error: Failed to generate a user access token.",
          error_detail: error
        } );

      }
    } );
  }

  async getTokenRPT( user_name, user_password, access_token ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Bearer ${access_token}`
        },
        data: {
          username: user_name,
          password: user_password,
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: "urn:ietf:params:oauth:grant-type:uma-ticket",
          audience: this.keycloakConfig.CLIENT_ID
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Rpt Token Generation Error: Failed to generate a refresh token.",
          error_detail: error
        } );

      }
    } );
  }

  async getIntrospectToken( access_token ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig[ "realm" ] + "/protocol/openid-connect/token/introspect";

      let config = {
        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          token: access_token
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, true );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {
          error_message: "Introspect Token Generation Error: Failed to generate an introspection token.",
          error_detail: error
        } );

      }
    } );
  }


  // function for getting user details against user id (and extracting attributes)
  async getUserDetailsById( userId ) {

    return new Promise( async ( resolve, reject ) => {

      let keycloakAdminToken;

      try {

        //Fetching admin token, we pass it in our "Create User" API for authorization
        keycloakAdminToken = await this.getAccessToken( this.keycloakConfig[ "USERNAME_ADMIN" ], this.keycloakConfig[ "PASSWORD_ADMIN" ] );

        let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId;

        let config = {
          method: "get",
          url: URL,
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Authorization": `Bearer ${keycloakAdminToken.access_token}`
          }
        };

        try {

          let userDetailsAgainstId = await requestController.httpRequest( config, true );

          if ( userDetailsAgainstId?.data ) {

            resolve( userDetailsAgainstId.data )    // extracting user details from response object
          }

        }
        catch ( er ) {

          let error

          if ( er?.status && er?.status === 404 ) {

            error = {
              status: 404,
              reason: `No user exist in keycloak against given user id: ${userId}`
            }

          } else {

            error = await errorService.handleError( er );
          }

          reject( {
            error_message: "User Details API Error: Error occurred while getting user against user id",
            error_detail: error
          } );

        }
      } catch ( er ) {

        console.log( er );

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Keycloak Admin Token Fetch Error: An error occurred while fetching the keycloak admin token in getUserDetailsById function.",
          error_detail: error
        } );

      }
    } );
  }

  // function for getting user details (and extracting attributes)
  async getUserDetails( adminToken, username ) {
    let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users?username=" + username + "&exact=true";
    let config = {
      method: "get",
      url: URL,
      headers: {
        Accept: "application/json",
        "cache-control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": `Bearer ${adminToken}`
      }
    };

    try {

      let userDetails = await requestController.httpRequest( config, true );

      if ( userDetails.data[ 0 ] ) {
        return userDetails.data[ 0 ];    // extracting user details from response object
      }
      else throw false;

    } catch ( error ) {
      let err = await errorService.handleError( error )
      return Promise.reject( { error_message: 'Error occurred while fetching user details.', error_detail: err } );
    }
  }

  // function for generating QR code and Secret code based on username
  async getQRCode( username ) {
    const secret = speakeasy.generateSecret( { name: username, symbols: false } )
    let image;
    try {
      image = await qrcode.toDataURL( secret.otpauth_url + "&issuer=EFCX" )
    } catch ( error ) {
      return false;
    }
    return { secret: secret.base32, image }
  }

  // function for updating user attributes in KeyCloak for 2FA registration
  async updateUserAttributes( adminToken, userId, attributesToUpdate ) {
    let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId;
    let config = {
      method: "put",
      url: URL,
      headers: {
        Accept: "application/json",
        "cache-control": "no-cache",
        "Content-Type": "application/json",
        "Authorization": `Bearer ${adminToken}`
      },
      data: {
        attributes: attributesToUpdate
      }
    };

    try {
      await requestController.httpRequest( config, false );
    } catch ( error ) {
      let err = await errorService.handleError( error )
      return Promise.reject( { error_message: 'Error occurred while updating user attributes.', error_detail: err } );
    }
  }

  // function for validating phone number
  isValidPhoneNumber( phoneNumber ) {
    return /^\d{7,15}$/.test( phoneNumber );
  }

  isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  // function for binding/registering phone number or email with user in Keycloak attributes - (callable from frontend)
  async registerCustomerChannelIdentifier( username, customerChannelId, appName, tenantId ) {
    if ( !this.isValidPhoneNumber( customerChannelId ) && !this.isValidEmail( customerChannelId ) ) {
      return Promise.reject( { error: 400, error_message: 'Invalid customerChannelIdentifier' } );
    }

    let userObjectToBeReturned = { username: username }

    const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN )
    const adminToken = adminData.access_token

    let userObject = await this.getUserDetails( adminToken, username )
    if ( !userObject.attributes ) {
      userObject.attributes = {}
    }

    // getting user attributes from the object and saving phoneNumber & additional information in KC
    if ( userObject.attributes ) {
      let userObjectAttributes = userObject.attributes
      let newAttributes = {}

      //checking if some attributes already exist
      if ( Object.keys( userObjectAttributes ).length > 0 ) {
        for ( let key in userObjectAttributes ) {
          newAttributes[ key ] = userObjectAttributes[ key ][ 0 ]
        }
      }
      newAttributes.customerChannelIdentifier = customerChannelId

      // saving customerChannelIdentifier & updating user attributes
      try {
        await this.updateUserAttributes( adminToken, userObject.id, newAttributes )
        newAttributes.appName = appName
        newAttributes.tenantId = tenantId
        try {
          await this.sendOTPviaOTPManager( username, newAttributes )          
        } catch (error) {
          return Promise.reject({
            error_message: 'An error occured while sending OTP via OTP Manager during customerChannelIdentifier registration.',
            error_detail: error
          })
        }

      } catch ( error ) {
        let err = await errorService.handleError( error )
        return Promise.reject( {
          error_message: 'Error occurred while registering customerChannelIdentifier.',
          error_detail: err
        } );
      }
    }
    else return Promise.reject( { error: 400, error_message: 'Error occurred while fetching user attributes.' } )

    // updating userObject that is returned to frontend
    userObjectToBeReturned.is2FARegistered = false
    userObjectToBeReturned.twoFAChannel = userObject.attributes.twoFAChannel[0]
    userObject.attributes.twoFAChannel[0] == 'SMS' 
      ? userObjectToBeReturned.phoneNumber = customerChannelId
      : userObjectToBeReturned.email = customerChannelId
    userObjectToBeReturned.message = 'OTP required'

    return userObjectToBeReturned
  }

  async sendOTPviaOTPManager(username, twoFAData) {
    const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN )
    const adminToken = adminData.access_token

    let userObject = await this.getUserDetails( adminToken, username )
    let customerChannelIdentifier = userObject.attributes.customerChannelIdentifier[0]

    let URL = this.keycloakConfig[ "Otp_Manager_Url" ] + "otp/generate";
    let config = {
      method: "post",
      url: URL,
      headers: {
        'Content-Type': 'application/json',
        'tenant-id': twoFAData.tenantId
      },
      data: {
        customerChannelIdentifier: customerChannelIdentifier,
        channelType: twoFAData.twoFAChannel ? twoFAData.twoFAChannel : twoFAData.channelType,
        channelServiceIdentifier: twoFAData.channelServiceIdentifier,
        appName: twoFAData.appName,
        otpExpiry: twoFAData.otpExpiry,
        otpMaxAttempts: twoFAData.otpMaxAttempts,
        purpose: "LOGIN"
      }
    };

    let otpManagerResponse;
    try {
      otpManagerResponse = await requestController.httpRequest(config, false);
    } catch (error) {
      return Promise.reject(error.response.data)
    }
    return Promise.resolve(otpManagerResponse.data)
  }

  async verifyOTPviaOTPManager(twoFAData, otp, appName, tenantId){
    let URL = this.keycloakConfig[ "Otp_Manager_Url" ] + "otp/verify";
    let config = {
      method: "post",
      url: URL,
      headers: {
        'Content-Type': 'application/json',
        'tenant-id': tenantId
      },
      data: {
        customerChannelIdentifier: twoFAData.customerChannelIdentifier,
        channelServiceIdentifier: twoFAData.channelServiceIdentifier,
        appName: appName,
        otpCode: otp,
        purpose: "LOGIN"
      }
    };

    let otpManagerResponse;
    try {
      otpManagerResponse = await requestController.httpRequest(config, false);
    } catch (error) {
      return Promise.reject(error.response.data)
    }
    return Promise.resolve(otpManagerResponse.data)
  }

  // function for validating OTP sent through authenticator app or SMS - (callable from frontend)
  async validateOTP( username, password, realm, otpToValidate, appName, tenantId ) {
    const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN )
    const adminToken = adminData.access_token

    // getting user details for fetching attributes and otpSecret or OTP validation
    let userDetails = await this.getUserDetails( adminToken, username )
    if ( userDetails.attributes ) {
      let userAttributes = userDetails.attributes

      if ( !userAttributes.is2FARegistered ) {
        return Promise.reject( {
          error: 404,
          error_message: 'Error occurred while verifying the 2FA registration. This may be because the user has not registered for 2FA.'
        } )
      }

      // running OTP validation flow for authenticator app
      if ( userAttributes.twoFAChannel[ 0 ] == 'APP' ) {
        let secret = userAttributes.otpSecret ? userAttributes.otpSecret[ 0 ] : userAttributes.tempOTPSecret[ 0 ]

        const verified = speakeasy.totp.verify( { secret: secret, encoding: 'base32', token: otpToValidate } );
        if ( !verified ) return Promise.reject( { error: 401, error_message: 'Invalid OTP.' } );

        // updating user attributes if he is registering for 2FA using G-Auth OTP
        if ( userAttributes.is2FARegistered[ 0 ] == 'false' ) {
          let newAttributes = {}
          for ( let key in userAttributes ) {
            newAttributes[ key ] = userAttributes[ key ][ 0 ]
          }
          if ( newAttributes.tempOTPSecret ) {
            newAttributes.otpSecret = newAttributes.tempOTPSecret
            delete newAttributes.tempOTPSecret
          }
          newAttributes.is2FARegistered = true

          this.updateUserAttributes( adminToken, userDetails.id, newAttributes )
        }
      }

      // running OTP validation flow for RSA Authenticator
      else if ( userAttributes.twoFAChannel[ 0 ] === 'RSA' ) {
        // setting up SecurID API for MFA
        let URL = this.keycloakConfig.RSA_Server_URL + "mfa/v1_1/authn/initialize";

        // configuring headers & payload
        let config = {
          method: "post",
          url: URL,
          headers: {
            "Content-Type": "application/json",
            "client-key": this.keycloakConfig.RSA_Client_Key,
          },
          data: {
            clientId: this.keycloakConfig.RSA_Client_ID,
            subjectName: username,
            subjectCredentials: [
              {
                methodId: "SECURID",
                collectedInputs: [ { name: "SECURID", value: otpToValidate } ],
              },
            ],
            context: {
              authnAttemptId: "",
              messageId: username + "2faAttempt",
              inResponseTo: "",
            },
          },
        };

        try {
          let verificationStatus = await requestController.httpRequest( config, false );
          if ( verificationStatus.status !== 200 || !verificationStatus.data || ( verificationStatus.data.attemptResponseCode !== 'SUCCESS' && verificationStatus.data.attemptReasonCode !== 'CREDENTIAL_VERIFIED' ) ) {
            throw false
          }
        }
        catch ( err ) {
          return Promise.reject( { error: 400, error_message: "Error occured while verifying token from RSA SecurID. This may be due to invalid token, invalid configurations or some issue with SecurID." } )
        }

      }

      // running OTP validation flow for SMS and Email
      else if ( ["SMS", "EMAIL"].includes(userAttributes?.twoFAChannel[ 0 ]) ) {
        try {
          let twoFAConfigs = {}

          // fetch 2fa configs from user attributes
          if ( Object.keys( userAttributes ).length > 0 ) {
            for ( let key in userAttributes ) {
              twoFAConfigs[ key ] = userAttributes[ key ][ 0 ]
            }
          }

          await this.verifyOTPviaOTPManager(twoFAConfigs, otpToValidate, appName, tenantId)
          
          // updating user attributes if he is registering for 2FA using SMS or Email OTP
          if ( userAttributes.is2FARegistered[ 0 ] == 'false' ) {
            twoFAConfigs.is2FARegistered = true
            this.updateUserAttributes( adminToken, userDetails.id, twoFAConfigs )
          }

        } catch ( error ) {
          let error_message = 'An error occured while verifying OTP via OTP Manager.'
          if (error.message == 'OTP_INVALID') error_message = 'Invalid verification code. Please try again.'
          else if(error.message == 'OTP_EXPIRED') error_message = 'This verification code has expired. Please request a new one.'
          else if(error.message == 'OTP_MAX_ATTEMPTS') error_message = 'Too many incorrect attempts. Verification has been temporarily blocked.'

          return Promise.reject({
            error_message: error_message,
            error_detail: error
          })
        }
      }
    }
    else return Promise.reject( { error: 400, error_message: 'Error occurred while fetching user attributes.' } )
    
    const userToken = await this.authenticateUserViaKeycloak( username, password, realm )
    
    // deleting twoFAConfigs data from response
    delete userToken.keycloak_User.attributes.otpSecret
    delete userToken.keycloak_User.attributes.tempOTPSecret
    delete userToken.keycloak_User.attributes.customerChannelIdentifier
    delete userToken.keycloak_User.attributes.channelType
    delete userToken.keycloak_User.attributes.channelServiceIdentifier
    delete userToken.keycloak_User.attributes.otpExpiry
    delete userToken.keycloak_User.attributes.otpMaxAttempts

    return userToken
  }

  // function for resetting/updating user password
  async resetPassword( username, currentPassword, newPassword ) {

    let updatePasswordFlag = false;

    try {
      // check if currentPassword is valid
      await this.getAccessToken( username, currentPassword );
      updatePasswordFlag = true;
    } catch ( error ) {
      if ( error.error_detail.status === 400 ) updatePasswordFlag = true;
      else {
        if ( error.error_detail.status === 401 ) {
          error.error_message = "Invalid User Credentials";
          error.error_detail.reason = "Invalid User Credentials: Current user credentials are not valid while updating password. Please enter valid user credentials.";
        }
        else error.error_message = "An error occured while updating the password. Please try again.";

        return Promise.reject( error );
      }
    }

    if ( updatePasswordFlag ) {
      // getting admin token to update password
      try {
        const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN );
        const adminToken = adminData.access_token;

        // check if password age policy is satisfied OR user is eligible to update password
        if(this.keycloakConfig["MINIMUM_PASSWORD_AGE_IN_HOURS"]){
          try {
            const passwordAgePolicyDetails = await this.getPasswordAgePolicyDetails(adminToken, username);
            if (passwordAgePolicyDetails) {
              const passwordAge = this.keycloakConfig["MINIMUM_PASSWORD_AGE_IN_HOURS"];
              const passwordAgeInDays = passwordAge % 24 === 0 ? passwordAge / 24 : null;
              const dayInfo = passwordAgeInDays
                ? `(${passwordAgeInDays} ${passwordAgeInDays > 1 ? 'days' : 'day'}) `
                : '';
              return Promise.reject({
                error_message: "An error occurred while updating the password. Please try later.",
                error_detail: {
                  status: 403,
                  reason: `Password must be at least ${passwordAge} hours ${dayInfo}old before updating. You can change your password on or after ${passwordAgePolicyDetails.eligibleToUpdatePasswordAt}.`,
                },
              });
            }
          } catch (error) {
            return Promise.reject(error); 
          }
        }

        // fetching userId from Keycloak to update the password        
        try {
          const usersData = await this.getUserDetails( adminToken, username );
          if ( usersData ) {
            const userId = usersData.id;

            // updating user password using userId
            let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId + "/reset-password";
            let config = {
              method: "put",
              url: URL,
              headers: {
                Accept: "application/json",
                "cache-control": "no-cache",
                "Content-Type": "application/json",
                Authorization: `Bearer ${adminToken}`,
              },
              data: {
                type: "password",
                temporary: false,
                value: newPassword,
              },
            };

            try {
              await requestController.httpRequest( config, false );
              return Promise.resolve( {
                status: 204,
                message: "Password updated successfully.",
              } );
            } catch ( error ) {
              let errorToReturn = {
                error_message: 'An error occured while updating the password. Please try again.',
                error_detail: {
                  status: error.status,
                  reason: error.response.data.error_description ? error.response.data.error_description : error.response.data.error
                }
              }

              return Promise.reject( errorToReturn )
            }
          }

        } catch ( error ) {
          let err = await errorService.handleError( error );
          return Promise.reject( {
            error_message: "Error occurred while fetching user attributes during password update.",
            error_detail: err,
          } );
        }

      } catch ( error ) {
        error = await errorService.handleError( error );
        return Promise.reject( {
          error_message: "Admin Token Generation Error: Failed to generate an admin access token in password update process.",
          error_detail: error,
        } );
      }
    }
  }

  // function for fetching password policies to be displayed on frontend
  async getPasswordPolicies(username){
    const result = { policies: [] };
    try {
      // get admin token to fetch password policies
      const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN );
      const adminToken = adminData.access_token;

      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ];
      let config = {
        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "Bearer " + adminToken
        }
      }

      try {
        // get realm settings to fetch passwordPolicies
        const realmInfo = await requestController.httpRequest( config, true );
        const passwordPolicies = realmInfo.data.passwordPolicy;

        // check and return details if password age policy is configured
        if( this.keycloakConfig["MINIMUM_PASSWORD_AGE_IN_HOURS"] ){
          try {
            const passwordAgePolicyDetails = await this.getPasswordAgePolicyDetails(adminToken, username);
            if(passwordAgePolicyDetails){
              Object.entries(passwordAgePolicyDetails).forEach( ([key, value]) => {
                result.policies.push({ type: key, value: value });
              });        
            }
          } catch (error) {
            return Promise.reject(error);
          }
        }

        if (!passwordPolicies) return Promise.resolve( result );      // if no policy is set

        // fetch policies from string and construct json response
        const policies = passwordPolicies.split( " and " ).filter( Boolean );
        policies.forEach( policy => {
          const match = policy.match( /^(\w+)\(([\s\S]*)\)$/ );
          if ( !match ) return;
          const [ , type, value ] = match;
          result.policies.push( { type, value: value === "undefined" ? "" : value } );
        } );

      } catch ( error ) {

        let error_message = "An error occurred while fetching password policies.";
        let error_detail = await errorService.handleError( error );
        return Promise.reject( { error_message, error_detail } );

      }

    } catch ( error ) {

      error.error_message = "Admin Token Generation Error: Failed to generate an admin access token while fetching password policies."
      return Promise.reject( error )

    }

    return Promise.resolve( result )

  }

  // function to check the password expiration and return a warning/message
  async checkPasswordExpiration( username ) {
    try {
      // get admin token to fetch credentials' details
      const adminData = await this.getAccessToken( this.keycloakConfig.USERNAME_ADMIN, this.keycloakConfig.PASSWORD_ADMIN );
      const adminToken = adminData.access_token;

      try {
        // get User ID to fetch user credentials
        const userDetails = await this.getUserDetails( adminToken, username );
        const userId = userDetails.id;

        let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId + "/credentials";
        let config = {
          method: "get",
          url: URL,
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer " + adminToken
          }
        };

        try {
          // fetch user credentials' details and calculate password expiry limit
          const credentialsDetails = await requestController.httpRequest( config, true );
          const creationTimestamp = credentialsDetails.data[ 0 ].createdDate;
          const currentTimestamp = Date.now();

          const creationDate = new Date( creationTimestamp );
          const currentDate = new Date( currentTimestamp );

          const diffInMs = Math.abs( currentDate - creationDate );      // calculate difference in milliseconds
          const diffInDays = Math.floor( diffInMs / ( 1000 * 60 * 60 * 24 ) );      // convert milliseconds to days

          // fetch password expiry limit
          let expiryLimit;
          try {
            expiryLimit = await this.getPasswordExpiryLimit( config );
            if ( expiryLimit === 0 ) return null;
          } catch ( error ) {
            return Promise.reject( error );
          }

          // calculate expiry date
          const expiryTimestamp = creationTimestamp + expiryLimit * 24 * 60 * 60 * 1000;
          const expiryDate = new Date( expiryTimestamp );
          const convertedExpiryTime = expiryDate.toLocaleDateString( 'en-US' );

          // calculate remaining days to show warning/message
          const remainingDays = expiryLimit - diffInDays;
          if ( remainingDays > 0 && remainingDays <= this.keycloakConfig[ "PASSWORD_EXPIRY_WARNING_LIMIT" ] ) {
            return Promise.resolve( `Please update your password. It will expire in ${remainingDays} day(s), on ${convertedExpiryTime}.` );
          }
          return Promise.resolve( null );

        } catch ( error ) {
          error = await errorService.handleError( error );
          return Promise.reject( {
            error_message: "Error occured while fetching User Credentials.",
            error_detail: error
          } );
        }
      } catch ( error ) {
        error.error_message = "Error occurred while fetching user details during Password Expiration check.";
        return Promise.reject( error );
      }
    } catch ( error ) {
      error = await errorService.handleError( error );
      return Promise.reject( {
        error_message: "Admin Token Generation Error: Failed to generate an admin access token during Password Expiration check.",
        error_detail: error
      } );
    }
  }

  // function to fetch password expiry limit from realm settings
  async getPasswordExpiryLimit( config ) {
    config.url = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ];
    try {
      const realmDetails = await requestController.httpRequest( config, true );
      if ( realmDetails.data.passwordPolicy ) {
        const passwordPolicy = realmDetails.data.passwordPolicy;

        // regex to extract days for password expiration
        const regex = /forceExpiredPasswordChange\((\d+)\)/;
        const match = passwordPolicy.match( regex );

        if ( match ) {
          return parseInt( match[ 1 ], 10 );
        } else {
          return 0;
        }
      }
      return 0;
    } catch ( error ) {
      error = await errorService.handleError( error );
      return Promise.reject( {
        error_message: "Error occured while fetching realm settings during password expiration check.",
        error_detail: error
      } );
    }
  }

  // function to fetch password age policy details
  async getPasswordAgePolicyDetails(adminToken, username){
    try {
      const userDetails = await this.getUserDetails(adminToken, username);      // fetch userId
      const userId = userDetails.id;

      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId + "/credentials";
      let config = {
        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "Bearer " + adminToken
        }
      };

      try {
        // fetch user credentials' details and calculate password age
        const credentialsDetails = await requestController.httpRequest( config, true );
        const creationTimestamp = credentialsDetails.data[ 0 ].createdDate;
        const currentTimestamp = Date.now();

        const creationDate = new Date( creationTimestamp );
        const currentDate = new Date( currentTimestamp );

        const diffInMs = Math.abs( currentDate - creationDate );      // difference in ms
        const diffInHours = Math.floor( diffInMs / ( 1000 * 60 * 60 ) );      // ms to hours
        const minPasswordAgeInMs = this.keycloakConfig['MINIMUM_PASSWORD_AGE_IN_HOURS'] * 60 * 60 * 1000; // hours to ms

        if(diffInHours < this.keycloakConfig['MINIMUM_PASSWORD_AGE_IN_HOURS']){
          // calculate the eligibility date/time by adding MINIMUM_PASSWORD_AGE_IN_HOURS to the creationDate
          const eligibleToUpdatePasswordDate = new Date(creationDate.getTime() + minPasswordAgeInMs);

          // response object containing necessary password age policy details
          let response = {
              'passwordCreatedAt': creationDate.toLocaleString(),
              'minPasswordAgeInHours': this.keycloakConfig['MINIMUM_PASSWORD_AGE_IN_HOURS'],
              'eligibleToUpdatePasswordAt': eligibleToUpdatePasswordDate.toLocaleString()
          };

          return Promise.resolve(response)

        }

        // return null when no password age policy is configured
        return Promise.resolve()

      } catch (error) {
        error = await errorService.handleError( error );
        return Promise.reject( {
          error_message: "User Credentials Error: Unable to fetch user credentials while getting Password Age Policy details.",
          error_detail: error
        } );
      }

    } catch (error) {
      error.error_message = 'User Details Error: Unable to fetch user information while getting Password Age Policy details.'
      return Promise.reject(error)
    }
  }

  async getKeycloakTokenWithIntrospect( user_name, user_password, realm_name, type ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let refresh_token;
      let error;
      let responseObject;

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + realm_name + "/protocol/openid-connect/token";

      //keycloakConfig["auth-server-url"] +'realms
      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          username: user_name,
          password: user_password,
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE,
        },

      };

      try {

        //  T.O.K.E.N   R.E.Q.U.E.S.T   # 1   ( P.E.R.M.I.S.S.I.O.N.S   N.O.T    I.N.C.L.U.D.E.D)
        let tokenResponse = await requestController.httpRequest( config, true );

        if ( tokenResponse.data.access_token ) {

          token = tokenResponse.data.access_token;
          refresh_token = tokenResponse.data.refresh_token;

          //To fetch introspect token to handle errors.
          let config_introspect = { ...config };
          config_introspect.data.token = token;
          delete config_introspect.data.username;
          delete config_introspect.data.password;

          config_introspect.url = URL + "/introspect";

          try {

            let intro_token_response = await requestController.httpRequest( config_introspect, true );

            if ( Object.keys( intro_token_response.data ).length > 0 ) {

              try {

                let config1 = { ...config };
                config1.data.username = this.keycloakConfig.USERNAME_ADMIN;
                config1.data.password = this.keycloakConfig.PASSWORD_ADMIN;
                delete config1.data.token;

                config1.url = this.keycloakConfig[ "auth-server-url" ] + "realms/" + realm_name + "/protocol/openid-connect/token";

                let adminTokenResponse = await requestController.httpRequest( config1, true );

                if ( adminTokenResponse.data.access_token ) {

                  let admin_token = adminTokenResponse.data.access_token;

                  try {

                    config1.headers.Authorization = "Bearer " + admin_token;
                    config1.method = "get";
                    config1.url = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + realm_name + "/users?username=" + user_name + "&exact=true";
                    delete config1.data;

                    let getuserDetails = await requestController.httpRequest( config1, true );

                    if ( getuserDetails.data.length !== 0 ) {

                      responseObject = {

                        id: getuserDetails.data[ 0 ].id,
                        firstName: getuserDetails.data[ 0 ].firstName ? getuserDetails.data[ 0 ].firstName : "",
                        lastName: getuserDetails.data[ 0 ].lastName ? getuserDetails.data[ 0 ].lastName : "",
                        username: getuserDetails.data[ 0 ].username,
                        roles: ( 'realm_access' in intro_token_response.data && 'roles' in intro_token_response.data.realm_access ) ? intro_token_response.data.realm_access.roles : [],
                        realm: realm_name,

                      };

                      //Adding user custom attribute to our token object data.
                      if ( getuserDetails.data[ 0 ].attributes ) {

                        responseObject.attributes = getuserDetails.data[ 0 ].attributes;
                      } else {

                        responseObject.attributes = {};
                      }

                      delete config1.headers.Authorization;
                      delete config1.data;

                      //Fetching Groups data for each user.
                      try {

                        let teamData = await this.getUserSupervisedGroups( responseObject.id, admin_token, type, responseObject?.roles );

                        //Check for Permission Groups assignment and roles assignment against them
                        const checkUserRoleAndPermissions = this.checkUserRoleAndPermissions( teamData, responseObject );

                        if ( checkUserRoleAndPermissions.error ) {

                          reject( {
                            error_message: "Token Generation Error: Failed to generate a user access token.",
                            error_detail: {
                              status: 403,
                              reason: checkUserRoleAndPermissions.message
                            }
                          } );
                        }

                        delete teamData.permissionGroups;

                        responseObject.userTeam = teamData.userTeam;
                        responseObject.supervisedTeams = teamData.supervisedTeams;

                      } catch ( er ) {

                        reject( er );
                      }

                    } else {

                      reject( {
                        error_message: "User Details Fetch Error: Could not retrieve user information during login.",
                        error_detail: {
                          status: 404,
                          reason: `User Not Found: The specified username ${user_name} does not exist.`
                        }
                      } );

                    }


                  } catch ( er ) {

                    error = await errorService.handleError( er );

                    reject( {
                      error_message: "Admin Token Generation Error: Failed to generate an admin access token.",
                      error_detail: error
                    } );
                  }
                }

              } catch ( er ) {

                error = await errorService.handleError( er );

                reject( {
                  error_message: "Admin Token Generation Error: Failed to generate an admin access token in user authentication process.",
                  error_detail: error
                } );

              }
            }

            config = {

              method: "post",
              url: URL,
              headers: {
                Accept: "application/json",
                "cache-control": "no-cache",
                "Content-Type": "application/x-www-form-urlencoded",
              },
              data: {
                username: user_name,
                password: user_password,
                client_id: this.keycloakConfig.CLIENT_ID,
                client_secret: this.keycloakConfig.credentials.secret,
                grant_type: this.keycloakConfig.GRANT_TYPE,
              },

            };

            config.data.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket";
            config.data.audience = this.keycloakConfig.CLIENT_ID;
            config.headers.Authorization = "Bearer " + token;

            //  T.O.K.E.N   R.E.Q.U.E.S.T   # 2   (A.C.C.E.S.S   T.O.K.E.N   W.I.T.H   P.E.R.M.I.S.S.I.O.N.S)
            try {

              let rptResponse = await requestController.httpRequest( config, true );

              if ( rptResponse.data.access_token ) {
                let rpt_token = rptResponse.data.access_token;

                let userToken = token;
                config.data.grant_type = this.keycloakConfig.GRANT_TYPE;
                config.data.token = rpt_token;
                URL = URL + "/introspect";
                config.url = URL;

                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 3   (A.C.C.E.S.S   T.O.K.E.N   I.N.T.R.O.S.P.E.C.T.I.O.N)
                try {

                  let intrsopectionResponse = await requestController.httpRequest( config, true );
                  intrsopectionResponse.data.access_token = rpt_token;

                  responseObject.permittedResources = {
                    Resources: ( intrsopectionResponse?.data?.authorization?.permissions?.length > 0 ) ? intrsopectionResponse?.data?.authorization?.permissions : []
                  }

                  //  T.O.K.E.N   R.E.Q.U.E.S.T   # 4   ( A.D.M.I.N.  T.O.K.E.N)

                  let finalObject = {

                    token: userToken,
                    refresh_token: refresh_token,
                    keycloak_User: responseObject,

                  };

                  resolve( finalObject );

                } catch ( er ) {

                  error = await errorService.handleError( er );

                  reject( {
                    error_message: "Introspect Token Generation Error: Failed to generate an introspection token in user authentication process.",
                    error_detail: error
                  } );

                }

              }

            } catch ( er ) {

              error = await errorService.handleError( er );

              reject( {
                error_message: "Rpt Token Fetch Error: Could not fetch the refresh token. Please ensure the user has the necessary roles, permissions, and groups" +
                  ". e.g: agent user must be assigned agent role, agents_permission group & all required permissions are created" +
                  ". every user must be assigned one team, if user is not part of any team then assign default team to User.",
                error_detail: {
                  "status": 403,
                  "reason": "Missing role, team, or permissions to log in. Please check with your administrator."
                }
              } );

            }



          } catch ( er ) {

            error = await errorService.handleError( er );

            reject( {
              error_message: "Token Generation Error: Failed to generate a user access introspect token.",
              error_detail: error
            } );

          }
        }

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Token Generation Error: Failed to generate a user access token.",
          error_detail: error
        } );

      }
    } );
  }

  // Function to check user roles and permissions
  checkUserRoleAndPermissions( teamData, responseObject ) {

    // Extract and clean up user roles
    const userRoles = responseObject.roles.filter(
      role => ![ 'default-roles-expertflow', 'offline_access', 'uma_authorization' ].includes( role )
    );

    const userTeam = teamData.userTeam || {};
    const permissionGroups = teamData.permissionGroups || [];

    // Check role flags
    const isAgent = userRoles.includes( 'agent' );
    const isSupervisor = userRoles.includes( 'supervisor' );

    // Check permission flags
    const hasSeniorAgentsPermission = permissionGroups.includes( 'senior_agents_permission' );
    const hasAgentsPermission = permissionGroups.includes( 'agents_permission' );

    // Check for basic requirements
    const hasRoles = userRoles.length > 0;
    const hasTeam = Object.keys( userTeam ).length > 0;
    const hasPermissions = permissionGroups.length > 0;

    // Basic validation checks
    if ( !hasRoles && !hasPermissions && !hasTeam ) {
      return {
        error: true,
        message: 'Missing role, team, or permissions to log in. Please check with your administrator.'
      };
    }

    if ( !hasRoles && !hasPermissions ) {
      return {
        error: true,
        message: 'Missing role or permissions to log in. Please check with your administrator.'
      };
    }

    if ( !hasRoles && !hasTeam ) {
      return {
        error: true,
        message: 'Missing team or role to log in. Please check with your administrator.'
      };
    }

    if ( !hasRoles ) {
      return {
        error: true,
        message: 'No roles are assigned to log in. Please check with your administrator.'
      };
    }

    // Role-specific validation

    // Case 1: User is both agent and supervisor
    if ( isAgent && isSupervisor ) {

      if ( !hasTeam && !hasSeniorAgentsPermission ) {
        return {
          error: true,
          message: 'Missing team or permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasSeniorAgentsPermission ) {
        return {
          error: true,
          message: 'You do not have the required permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasTeam ) {
        return {
          error: true,
          message: 'You are not a part of any team. Please check with your administrator.'
        };
      }
    }

    // Case 2: User is supervisor only
    else if ( isSupervisor ) {
      if ( !hasTeam && !hasPermissions ) {
        return {
          error: true,
          message: 'Missing team or permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasPermissions ) {
        return {
          error: true,
          message: 'You do not have the required permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasTeam && !hasSeniorAgentsPermission ) {
        return {
          error: true,
          message: 'Missing team or permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasSeniorAgentsPermission ) {
        return {
          error: true,
          message: 'You do not have the right permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasTeam && hasSeniorAgentsPermission ) {
        return {
          error: true,
          message: 'You are not a part of any team. Please check with your administrator.'
        };
      }
    }

    // Case 3: User is agent only
    else if ( isAgent ) {
      if ( !hasTeam && !hasPermissions ) {
        return {
          error: true,
          message: 'Missing team or permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasPermissions ) {
        return {
          error: true,
          message: 'You do not have the required permissions to log in. Please check with your administrator.'
        };
      }

      if ( !hasTeam && ( hasAgentsPermission || hasSeniorAgentsPermission ) ) {
        return {
          error: true,
          message: 'You are not a part of any team. Please check with your administrator.'
        };
      }
    }

    // If no error conditions are met
    return { error: false };
  }


  async getUserInfoFromToken( username, token ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token/introspect";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          username: username,
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          token: token,
        },

      };

      try {

        let userInfo = await requestController.httpRequest( config, true );

        if ( !userInfo.data.active ) {

          reject( {
            error_message: "Token Validation Error: An error occurred while retrieving user information from the token.",
            error_detail: {
              status: 401,
              reason: `Expired Token: The provided access token has expired. Please provide a valid access token.`
            }
          } );

        }

        let clientRoles = userInfo.data.resource_access;
        resolve( clientRoles );

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Token Validation Error: An error occurred while retrieving user information from the token.",
          error_detail: error
        } );
      }

    } );
  }

  //Client ID is required for Authorization Functionality
  async getClientId( token ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/clients?clientId=" + this.keycloakConfig[ "CLIENT_ID" ];

      let config = {
        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },
      };

      try {

        let result = await requestController.httpRequest( config, false );
        let clientId = result.data[ 0 ].id;

        resolve( clientId );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Client ID Fetch Error: An error occurred while fetching the client id in the client id component.",
          error_detail: error
        } );

      }

    } );
  }

  createResource( resource_name, resource_scope = this.keycloakConfig.SCOPE_NAME ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE_PAT,
        },

      };

      //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1
      try {

        let patToken = await requestController.httpRequest( config, true );

        if ( patToken.data.access_token ) {

          let token = patToken.data.access_token;
          //     C.R.E.A.T.E    R.E.S.O.U.R.C.E     R.E.Q.U.E.S.T
          delete config.data[ "client_id" ];
          delete config.data[ "client_secret" ];
          delete config.data[ "grant_type" ];

          config.data.name = resource_name;
          config.data._id = resource_name;
          config.data.resource_scopes = [ resource_scope ];

          config.url = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/authz/protection/resource_set";
          config.headers.Authorization = "Bearer " + token;
          config.headers[ "Content-Type" ] = "application/json";

          try {

            let resourceResponse = await requestController.httpRequest( config, false );
            resolve( resourceResponse );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Resource Creation Error: An error occurred while creating the resource.",
              error_detail: error
            } );

          }

        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "PAT Token Generation Error: An error occurred while generating the personal access token.",
          error_detail: error
        } );

      }
    } );

  }

  deleteResource( resource_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE_PAT,
        },

      };

      //  P.A.T   T.O.K.E.N   R.E.Q.U.E.S.T   # 1
      try {

        let patToken = await requestController.httpRequest( config, true );

        if ( patToken.data.access_token ) {

          token = patToken.data.access_token;
          //  D.E.L.E.T.E    R.E.S.O.U.R.C.E  A.N.D   P.E.R.M.I.S.S.I.O.N   R.E.Q.U.E.S.T
          let URL1 = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/authz/protection/resource_set/" + resource_name;

          config.url = URL1;
          config.method = "delete";
          config.headers.Authorization = "Bearer " + token;
          delete config.data[ "grant_type" ];
          config.data.name = resource_name;

          try {

            let resourceResponse = await requestController.httpRequest( config, true );

            //         // WE NEED admin token to delete policy
            //         /// admin token request
            config.method = "post";
            config.url = URL;
            delete config.headers[ "Authorization" ];
            config.data.client_id = this.keycloakConfig.CLIENT_ID;
            config.data.username = this.keycloakConfig.USERNAME_ADMIN;
            config.data.password = this.keycloakConfig.PASSWORD_ADMIN;
            config.data.grant_type = this.keycloakConfig.GRANT_TYPE;
            config.data.client_secret = this.keycloakConfig.credentials.secret;

            try {

              let adminTokenResponse = await requestController.httpRequest( config, true );
              token = adminTokenResponse.data.access_token;

              // now deleting policy
              config.method = "delete";
              delete config.data;
              let URL6 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/clients/" + this.keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/user/" + resource_name + "-policy";
              config.url = URL6;

              delete config.headers[ "Accept" ];
              delete config.headers[ "cache-control" ];
              delete config.headers[ "Content-Type" ];
              config.headers.Authorization = "Bearer " + token;

              try {

                let deletePolicy = await requestController.httpRequest( config, false );
                resolve( deletePolicy );

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                  error_message: "Auth Policy Deletion Error: An error occurred while deleting the authorization policy.",
                  error_detail: error
                } );
              }

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Admin Token Generation Error: An error occurred while generating the admin token.",
                error_detail: error
              } );

            }
          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Auth Resource Deletion Error: An error occurred while deleting the authorization resource.",
              error_detail: error
            } );

          }
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "PAT Token Generation Error: An error occurred while generating the personal access token.",
          error_detail: error
        } );
      }
    } );
  }

  //Get User Based Policy.
  async getPolicy( policyName, token, clientId ) {

    return new Promise( async ( resolve, reject ) => {


      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/clients/" + clientId + "/authz/resource-server/policy?name=" + policyName + "&exact=true";

      let config = {

        method: "get",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },

      };

      try {

        let result = await requestController.httpRequest( config, false );
        let policy = result.data[ 0 ];

        resolve( policy );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Policy Fetch Error: An error occurred while fetching the policy for team supervisor assignment during Finesse user creation.",
          error_detail: error
        } );
      }



    } );

  }

  createPolicy( policyName, roles ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          username: this.keycloakConfig.USERNAME_ADMIN,
          password: this.keycloakConfig.PASSWORD_ADMIN,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          client_secret: this.keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
        //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y
        let URL3 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/clients/" + this.keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/role";
        config.url = URL3;
        config.headers[ "Content-Type" ] = "application/json";
        config.headers.Authorization = "Bearer " + token;

        config.data.decisionStrategy = "AFFIRMATIVE";
        config.data.logic = "POSITIVE";
        config.data.name = policyName;
        config.data.type = "role";
        config.data.id = policyName;
        config.data.roles = roles;

        delete config.data[ "client_id" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        config.data = JSON.stringify( config.data );

        try {

          let policyResponse = await requestController.httpRequest( config, false );
          resolve( policyResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Role-Based Policy Creation Error: An error occurred while creating the role-based policy.",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token during policy creation.",
          error_detail: error
        } );
      }
    } );
  }

  //Update User Based Policy.
  async updateUserBasedPolicy( policyObj, token, clientId ) {

    return new Promise( async ( resolve, reject ) => {


      let policyId = policyObj.id;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/clients/" + clientId + "/authz/resource-server/policy/user/" + policyId;

      delete policyObj.id;

      let config = {

        method: "put",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        headers: {
          Authorization: "Bearer " + token,
        },
        data: policyObj,

      };

      try {

        let result = await requestController.httpRequest( config, false );
        let updatedPolicy = result.data;

        resolve( updatedPolicy );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "User-Based Policy Update Error: An error occurred while updating the user-based policy during Finesse user creation.",
          error_detail: error
        } );

      }

    } );
  }

  createPermission( resourceName, policyName, permissionName, scopeName ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          username: this.keycloakConfig.USERNAME_ADMIN,
          password: this.keycloakConfig.PASSWORD_ADMIN,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          client_secret: this.keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        //   T.O.K.E.N    R.E.Q.U.E.S.T  (user with admin is already defined in keycloak with roles 'realm-management')
        //   //  C.R.E.A.T.E    U.S.E.R    B.A.S.E.D    P.O.L.I.C.Y
        let URL3 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/clients/" + this.keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/permission/scope";
        config.url = URL3;
        config.headers[ "Content-Type" ] = "application/json";
        config.headers.Authorization = "Bearer " + token;

        config.data.decisionStrategy = "AFFIRMATIVE";
        config.data.logic = "POSITIVE";
        config.data.name = permissionName;
        config.data.policies = policyName;
        config.data.resources = resourceName;
        config.data.scopes = scopeName;
        config.data.type = "scope";
        config.data.id = permissionName;

        delete config.data[ "client_id" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        config.data = JSON.stringify( config.data );

        try {

          let policyResponse = await requestController.httpRequest( config, false );
          resolve( policyResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Auth Permission Creation Error: An error occurred during the creation of the authorization permission.",
            error_detail: error
          } );

        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token during permission creation.",
          error_detail: error
        } );
      }
    } );
  }

  //   R.E.S.O.U.R.C.E    A.U.T.H.O.R.I.Z.A.T.I.O.N        (    E.V.A.L.U.A.T.E    U.S.E.R    T.O   A    R.E.S.O.U.R.C.E   )
  resourceAuthorization( keycloak_user_id, resource_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          username: this.keycloakConfig.USERNAME_ADMIN,
          password: this.keycloakConfig.PASSWORD_ADMIN,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          client_secret: this.keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        // EVALUATION REQUEST
        let data = JSON.stringify( {
          resources: [ { _id: resource_name } ],
          clientId: this.keycloakConfig.CLIENT_DB_ID,
          userId: keycloak_user_id,
        } );

        config.data.clientId = this.keycloakConfig.CLIENT_DB_ID;
        config.data.resources = [ { _id: resource_name } ];
        config.data.userId = keycloak_user_id;
        delete config.data[ "username" ];
        delete config.data[ "password" ];
        delete config.data[ "grant_type" ];
        delete config.data[ "client_secret" ];
        delete config.data[ "client_id" ];

        let URL5 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/clients/" + this.keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/evaluate";
        config.url = URL5;
        config.headers[ "Content-Type" ] = "application/json";
        ( config.headers.Authorization = "Bearer " + token ), ( config.data = JSON.stringify( config.data ) );

        try {

          let evaluationResponse = await requestController.httpRequest( config, false );
          resolve( evaluationResponse );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Auth Evaluation Error: An error occurred during the authorization evaluation process.",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token during the resource evaluation process.",
          error_detail: error
        } );
      }
    } );
  }

  revokeUseronResource( resource_name, keycloak_user_id ) {

    return new Promise( async ( resolve, reject ) => {

      let token;

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          username: this.keycloakConfig.USERNAME_ADMIN,
          password: this.keycloakConfig.PASSWORD_ADMIN,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          client_secret: this.keycloakConfig.credentials.secret,
        },
      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;
        // now deleting policy
        config.method = "delete";
        delete config.data;
        let URL6 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/clients/" + this.keycloakConfig.CLIENT_DB_ID + "/authz/resource-server/policy/user/" + resource_name + "-policy";
        config.url = URL6;
        delete config.headers[ "Accept" ];
        delete config.headers[ "cache-control" ];
        delete config.headers[ "Content-Type" ];
        config.headers.Authorization = "Bearer " + token;

        try {

          let deletePolicy = await requestController.httpRequest( config, false );
          resolve( deletePolicy );

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Policy Deletion Error: An error occurred while deleting the policy.",
            error_detail: error
          } );
        }
      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token during policy deletion.",
          error_detail: error
        } );
      }

    } );
  }

  async getUserSupervisedGroups( userId, adminToken, type, roles ) {

    return new Promise( async ( resolve, reject ) => {

      let team = { userTeam: {}, supervisedTeams: [], permissionGroups: [] };
      let error;

      let config = {
        method: "get",
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
          "tenant-id": this.keycloakConfig[ "realm" ]
        },
      };

      try {

        // User Groups
        let URL = this.keycloakConfig[ "ef-server-url" ] + "team/user/" + userId;
        config.url = URL;

        try {

          let userTeams = await requestController.httpRequest( config, true );
          const { userTeam, supervisedTeams } = userTeams.data;

          if ( Object.keys( userTeam ).length == 0 && type != 'CX' ) {
            reject( {
              error_message: "User Team Fetch Error: An error occurred while fetching the user's team.",
              error_detail: {
                status: 403,
                reason: "Missing Team Group: No team group is assigned to the user. Please assign a team to the user. If the user has no team, assign the default group."
              }
            } );
          }

          team.userTeam = userTeam;
          team.supervisedTeams = supervisedTeams;

        } catch ( er ) {

          if ( !roles.includes( "admin" ) ) {

            error = await errorService.handleError( er );

            // Log the error and proceed with default values
            console.error( "User Team Fetch Error: An error occurred while fetching the user's team:", error );
          }

        }

        // User Groups from Keycloak
        let URL1 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/users/" + userId + "/groups";
        config.url = URL1;
        config.headers.Authorization = "Bearer " + adminToken;

        try {

          let userGroup = await requestController.httpRequest( config, true );

          if ( userGroup.data.length != 0 ) {

            let groups = userGroup.data;
            let permissionGroups = groups.filter( group => group.name.includes( "_permission" ) );

            if ( permissionGroups.length > 0 ) {

              team.permissionGroups = [];

              permissionGroups.forEach( perGroup => {
                team.permissionGroups.push( perGroup.name );
              } );
            }

          }
        } catch ( er ) {

          error = await errorService.handleError( er );
          // Log the error and proceed with default values
          console.error( "User Team Fetch Error: An error occurred while fetching the user's team:", error );
        }

        resolve( team );

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Admin Token Generation Error: An error occurred while generating the admin access token to fetch the user's team and supervised teams.",
          error_detail: error
        } );
      }
    } );
  }

  //function to be used only in teams implementation
  async getTeamUsers( keycloakObj, groupsIdsArr, userToken ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let message;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";



      if ( typeof keycloakObj == "object" && Object.keys( keycloakObj ).length != 0 && Array.isArray( groupsIdsArr ) && userToken.length > 0 ) {

        //Validate whether user in keycloakObj is same as user in userToken.
        const parseJwt = ( userToken ) => {

          try {

            return JSON.parse( Buffer.from( userToken.split( "." )[ 1 ], "base64" ).toString() );
          } catch ( er ) {

            return null;
          }

        };

        let verifyToken = parseJwt( userToken );

        if ( keycloakObj.username != verifyToken.preferred_username ) {

          message = `Invalid Keycloak Object: The data provided in the Keycloak object as an argument does not belong to the current logged-in user.`;

          resolve( {

            status: 401,
            message: message,

          } );

        }

        let config = {

          method: "post",
          url: URL,
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
          },
          data: {
            client_id: this.keycloakConfig.CLIENT_ID,
            username: this.keycloakConfig.USERNAME_ADMIN,
            password: this.keycloakConfig.PASSWORD_ADMIN,
            grant_type: this.keycloakConfig.GRANT_TYPE,
            client_secret: this.keycloakConfig.credentials.secret,
          },

        };

        try {

          let adminTokenResponse = await requestController.httpRequest( config, true );
          token = adminTokenResponse.data.access_token;

          let allUsers = [];
          let groupsData;

          config.method = "get";
          delete config.data;
          delete config.url;
          config.headers.Authorization = "Bearer " + token;

          let clientRoles = await this.getUserInfoFromToken( keycloakObj.username, userToken );

          if ( clientRoles.status ) {

            resolve( clientRoles );
          }

          //admin case
          if ( "realm-management" in clientRoles ) {

            let URL2 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/groups";
            config.url = URL2;

            try {

              let groups = await requestController.httpRequest( config, true );
              delete config.url;

              groupsData = groups.data;
              groupsData = groupsData.filter( ( group ) => !group.name.includes( "_permission" ) );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Groups Fetch Error: An error occurred while fetching the groups in the team users list component.",
                error_detail: error
              } );
            }

          } else {

            //agent case
            if ( keycloakObj.supervisedTeams.length == 0 ) {
              resolve( [] );

              //supervisor case
            } else {

              //if no group ids are provided, send all the users of groups this user supervises.
              if ( groupsIdsArr.length == 0 ) {

                let supervisedGroups = keycloakObj.supervisedTeams;
                supervisedGroups = supervisedGroups.filter( ( group ) => !group.teamName.includes( "_permission" ) );
                groupsData = supervisedGroups;

                //only send the users of provided groups.
              } else {

                let groupsArr = [];
                let idsArr = groupsIdsArr;

                idsArr.forEach( ( id ) => {

                  let group = keycloakObj.supervisedTeams.find( ( group ) => {
                    return group.teamId == id;
                  } );

                  if ( !group ) {

                    message = `No Supervised Groups: The given user does not supervise any group with the specified id: ${id}`;

                    resolve( {
                      status: 404,
                      message: message,
                    } );

                  }

                  groupsArr.push( group );

                } );

                groupsArr = groupsArr.filter( ( group ) => !group.teamName.includes( "_permission" ) );
                groupsData = groupsArr;

              }
            }
          }

          allUsers = await teamsService.getUsersOfGroups( groupsData, config, this.keycloakConfig );
          resolve( allUsers );

        } catch ( er ) {


          let error = await errorService.handleError( er );

          reject( {

            error_message: "Admin Token Generation Error: An error occurred while generating the admin token during the fetching of team users.",
            error_detail: error
          } );

        }
      }

      message = "Invalid Arguments: Please pass the valid arguments. First argument must be  (should not be empty object," +
        "must contain valid key-value pair) and Second argument must be Array of groupIds (could be an empty array)" +
        "3rd Argument must be valid Access Token of current logged-in user.";

      resolve( {

        status: 400,
        message: message,
      } );

    } );
  }

  //function to be used only in teams implementation. We give the list of ids of groups and it returns all its members and supervisors
  async getGroupMembers( groupIds ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let groupsData = [];
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          username: this.keycloakConfig.USERNAME_ADMIN,
          password: this.keycloakConfig.PASSWORD_ADMIN,
          grant_type: this.keycloakConfig.GRANT_TYPE,
          client_secret: this.keycloakConfig.credentials.secret,
        },

      };

      try {

        let adminTokenResponse = await requestController.httpRequest( config, true );
        token = adminTokenResponse.data.access_token;

        if ( groupIds.length > 0 ) {

          config.method = "get";
          delete config.data;
          delete config.url;
          config.headers.Authorization = "Bearer " + token;

          for ( let i = 0; i < groupIds.length; i++ ) {

            try {

              let groupData = {};

              let URL2 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/groups/" + groupIds[ i ] + "/";
              config.url = URL2;
              let groupInfo = await requestController.httpRequest( config, true );

              groupData.teamId = groupInfo.data.id;
              groupData.teamName = groupInfo.data.name;

              if ( Object.keys( groupInfo.data.attributes ).length == 0 ) {

                groupData.supervisors = [];
              } else {

                let attributes = groupInfo.data.attributes;

                if ( "supervisor" in attributes ) {

                  let supervisorList = attributes[ "supervisor" ][ 0 ].split( "," );
                  let supervisors = [];

                  for ( let j = 0; j < supervisorList.length; j++ ) {

                    let URL3 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/users?username=" + supervisorList[ j ] + "&exact=true";
                    config.url = URL3;

                    try {

                      let supervisorUser = await requestController.httpRequest( config, true );

                      if ( supervisorUser.data.length > 0 ) {

                        supervisors.push( {
                          supervisorId: supervisorUser.data[ 0 ].id,
                          supervisorName: supervisorUser.data[ 0 ].username,
                        } );
                      }

                    } catch ( er ) {

                      let error = await errorService.handleError( er );

                      reject( {

                        error_message: "Supervisor Users Fetch Error: An error occurred while fetching supervisor users in the team members list component.",
                        error_detail: error
                      } );
                    }
                  }

                  groupData.supervisors = supervisors;
                }
              }

              let URL4 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/groups/" + groupIds[ i ] + "/members";
              config.url = URL4;
              let users = await requestController.httpRequest( config, true );

              if ( users.data.length > 0 ) {

                let agents = users.data;
                agents = agents.map( ( agent ) => {

                  return {
                    agentId: agent.id,
                    agentName: agent.username,
                  };
                } );

                groupData.agents = agents;

              } else {

                groupData.agents = [];
              }

              groupsData.push( groupData );

            } catch ( err ) {

              if ( err.response && err.response.status !== 404 ) {

                let error = await errorService.handleError( err );

                reject( {

                  error_message: "Teams Fetch Error: An error occurred while fetching teams against team IDs in the team members list component.",
                  error_detail: error
                } );

              } else if ( err.message ) {

                if ( err.message !== "Request failed with status code 404" ) {

                  let error = await errorService.handleError( err );

                  reject( {

                    error_message: "Teams Fetch Error: An error occurred while fetching teams against team ids in the team members list component.",
                    error_detail: error
                  } );
                }

              } else {

                continue;
              }
            }
          }

          resolve( groupsData );
        }

        resolve( [] );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token in the team members list component.",
          error_detail: error
        } );

      }

    } );
  }

  // this function requires comma separated list of roles in parameter e.g ["robot","human","customer"];
  getUsersByRole( keycloak_roles ) {

    return new Promise( async ( resolve, reject ) => {

      let token;


      try {

        //Fetching admin token, we pass it in our "Create User" API for authorization
        let keycloakAuthToken = await this.getAccessToken( this.keycloakConfig[ "USERNAME_ADMIN" ], this.keycloakConfig[ "PASSWORD_ADMIN" ] );

        if ( keycloakAuthToken.access_token ) {

          token = keycloakAuthToken.access_token;

          let config = {
            method: "get",
            headers: {
              Accept: "application/json",
              "cache-control": "no-cache",
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization: `Bearer ${token}`
            }
          };

          let userObject = {}; // to read data object having all users of a certain role
          let count = 0;
          let flag = true;
          let obj = []; // final object to be returned

          for ( let i = 0; i < keycloak_roles.length; i++ ) {

            try {

              config.url = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig.realm + "/roles/" + keycloak_roles[ i ] + "/users?max=100000";
              let getUsersfromRoles = await requestController.httpRequest( config, true );
              userObject = getUsersfromRoles.data;

              userObject.forEach( ( user ) => {

                if ( count > 0 ) {

                  let userIndex = obj.findIndex( ( usr ) => {
                    return usr.username == user.username;
                  } );

                  if ( userIndex != -1 ) {
                    obj[ userIndex ].roles.push( keycloak_roles[ i ] );
                    flag = false;
                  }

                }

                if ( flag == true ) {

                  obj.push( {
                    id: user?.id,
                    username: user?.username,
                    firstName: user?.firstName == undefined ? "" : user?.firstName,
                    lastName: user?.lastName == undefined ? "" : user?.lastName,
                    attributes: ( user?.attributes ) ? user?.attributes : {},
                    roles: [ keycloak_roles[ i ] ],
                  } );

                }

                flag = true;
              } );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Users by Role Fetch Error: An error occurred while fetching users against roles in the get users by role component.",
                error_detail: error
              } );
            }

            count++;
          }

          resolve( obj );
        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Admin Token Generation Error: An error occurred while generating the admin token in the get users by role component.",
          error_detail: error
        } );
      }
    } );
  }

  async getRealmRoles( adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/roles`;

      let config = {
        method: "get",
        url: URL,
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, false );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Realm Roles Fetch Error: An error occurred while fetching realm roles.",
          error_detail: error
        } );

      }
    } );
  }

  async assignRoleToUser( userId, roles, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/users/${userId}/role-mappings/realm`;

      let config = {
        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        },
        data: roles,
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, false );
        resolve( tokenResponse );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Role Assignment Error: An error occurred while assigning the role to the user.",
          error_detail: error
        } );
      }
    } );
  }

  async getKeycloakUserGroups( userId, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/users/${userId}/groups/`;

      let config = {
        method: "get",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        }
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, false );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "User Groups Fetch Error: An error occurred while fetching the groups of the user using the user id.",
          error_detail: error
        } );
      }
    } );

  }

  async gettingGroupByGroupName( groupNames, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let groups = [];


      for ( let name of groupNames ) {

        let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/groups?search=${name}`;

        let config = {
          method: "get",
          url: URL,
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${adminToken}`,
          }
        };

        try {

          let tokenResponse = await requestController.httpRequest( config, false );
          let exactGroup;

          if ( tokenResponse.data.length > 1 ) {
            exactGroup = tokenResponse.data.find( group => group.name == name );

            groups.push( {
              id: exactGroup.id,
              name: exactGroup.name
            } );

          } else {

            groups.push( {
              id: tokenResponse.data[ 0 ].id,
              name: tokenResponse.data[ 0 ].name
            } );
          }

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Groups by Name Fetch Error: An error occurred while fetching groups using the group name.",
            error_detail: error
          } );
        }

      }

      resolve( groups );

    } );

  }

  async getGroupById( groupId, adminToken ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/groups/${groupId}/`;

      let config = {
        method: "get",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        }
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, false );
        let group = tokenResponse.data;
        resolve( group );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Group by ID Fetch Error: An error occurred while fetching the group using the group id.",
          error_detail: error
        } );
      }

    } );
  }

  async addOrRemoveUserGroup( userId, groups, operation, adminToken ) {


    return new Promise( async ( resolve, reject ) => {

      let method = ( operation == 'remove' ) ? 'delete' : 'put';

      let config = {
        method: method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        }
      };

      for ( let group of groups ) {

        let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/users/${userId}/groups/${group.id}`;
        config.url = URL;

        if ( method == 'put' ) {

          config.data = {
            realm: this.keycloakConfig[ "realm" ],
            userId: userId,
            groupId: group.id
          }
        }

        try {

          let tokenResponse = await requestController.httpRequest( config, false );

        } catch ( err ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "User Roles Modification Error: An error occurred while adding or removing roles of the user using the user id.",
            error_detail: error
          } );

        }

      }

      resolve( [] );

    } );

  }

  async addOrRemoveUserRole( userId, roles, operation, token ) {

    return new Promise( async ( resolve, reject ) => {

      let method = ( operation == 'remove' ) ? 'delete' : 'post';

      if ( realmRoles.length > 0 ) {

        let check = checkForMissingRole( realmRoles, roles );

        if ( !check ) {

          realmRoles = await this.getRealmRoles( token );
        }

      } else {

        realmRoles = await this.getRealmRoles( token );
      }

      let rolesArr = realmRoles.filter( role => roles.includes( role.name ) );

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/users/${userId}/role-mappings/realm`;

      let config = {

        method: method,
        url: URL,
        headers: {
          Authorization: `Bearer ${token}`,
        },
        data: rolesArr,
      };

      try {

        let tokenResponse = await requestController.httpRequest( config, false );
        resolve( tokenResponse.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "User Roles Modification Error: An error occurred while adding or removing roles of the user using the user id.",
          error_detail: error
        } );
      }
    } );
  }

  async createGroup( adminToken, groupName ) {

    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/groups`;

      let data = {
        name: groupName,
      };

      let config = {
        method: "post",
        url: URL,
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
        data: data,
      };

      try {

        let createdGroup = await requestController.httpRequest( config, false );
        resolve( createdGroup.data );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "Group Creation Error: An error occurred while creating the group in the create group component.",
          error_detail: error
        } );
      }

    } );
  }

  //Authenticating Finesse User
  async authenticateFinesse( username, password, finesseUrl, userRoles, finesseToken ) {

    return new Promise( async ( resolve, reject ) => {

      //Authentication of Finesse User, it returns a status code 200 if user found and 401 if unauthorized.
      let finesseLoginResponse;

      try {
        //Handle finesse error cases correctly. (for later)
        if ( finesseToken.length == 0 ) {

          finesseLoginResponse = await finesseService.authenticateUserViaFinesse( username, password, finesseUrl );

        } else {


          finesseLoginResponse = await finesseService.authenticateUserViaFinesseSSO( username, finesseToken, finesseUrl );
        }

        //If user is SSO then password is not provided, we are setting up a pre-defined password.
        password = password.length == 0 ? "123456" : password;
        finesseLoginResponse.data.password = password;

        let authenticatedByKeycloak = false;
        let keycloakAuthToken = null;
        let keycloakAdminToken = null;
        let updateUserPromise = null;

        if ( finesseLoginResponse.status == 200 ) {

          try {

            //Fetching admin token, we pass it in our "Create User" API for authorization
            keycloakAdminToken = await this.getAccessToken( this.keycloakConfig[ "USERNAME_ADMIN" ], this.keycloakConfig[ "PASSWORD_ADMIN" ] );

            try {

              //Checking whether finesse password is updated or not. If updated, update it on keycloak as well without halting login process
              await this.checkPasswordUpdate( keycloakAdminToken.access_token, finesseLoginResponse.data.username, password );
              //Checking whether finesse user already exist in keycloak and fetch its token
              keycloakAuthToken = await this.getAccessToken( finesseLoginResponse.data.username, password, this.keycloakConfig[ "realm" ] );
              authenticatedByKeycloak = true;

              if ( !updateUserPromise ) {

                updateUserPromise = this.updateUser( finesseLoginResponse.data, keycloakAdminToken, keycloakAuthToken, finesseLoginResponse.data.username, password )
                  .then( async ( updatedUser ) => {

                    //Calling the Introspect function twice so all the asynchronous operations inside updateUser function are done
                    keycloakAuthToken = await this.getKeycloakTokenWithIntrospect( finesseLoginResponse.data.username, password, this.keycloakConfig[ "realm" ], 'CISCO' );
                  } )
                  .catch( ( err ) => {

                    reject( err );
                  } );
              }


            } catch ( err ) {

              if ( err.error_detail ) {

                if ( err.error_detail.status == 401 ) {

                  console.log( "User Not Found in Keycloak: The user does not exist in Keycloak. Syncing Finesse user in Keycloak." );
                } else {

                  reject( err );
                }
              } else {

                reject( err );
              }

            }
          } catch ( err ) {

            let error = await errorService.handleError( err );

            reject( {

              error_message: "Keycloak Admin Token Fetch Error: An error occurred while fetching the keycloak admin token in the authenticate/sync finesse user component.",
              error_detail: error
            } );


          } finally {

            //Finesse User not found in keycloak, so we are going to create one.
            if ( !authenticatedByKeycloak ) {

              if ( keycloakAdminToken.access_token ) {

                let token = keycloakAdminToken.access_token;

                //validating customer Before Creation
                let { error, value } = validateUser( {
                  username,
                  password,
                  token,
                  userRoles,
                } );

                if ( error ) {

                  reject( {
                    status: 400,
                    message: "User Creation Error: An error occurred while creating the user. Error message: " + error.details[ 0 ].message,
                  } );
                }
              }

              try {

                //Creating Finesse User inside keycloak.
                let userCreated = await this.createUser( finesseLoginResponse.data, keycloakAdminToken.access_token );

                if ( userCreated.status == 201 ) {

                  //Returning the token of recently created User
                  keycloakAuthToken = await this.getKeycloakTokenWithIntrospect( ( finesseLoginResponse.data.username ).toLowerCase(), password, this.keycloakConfig[ "realm" ], 'CISCO' );
                }

              } catch ( err ) {


                let error = await errorService.handleError( err );

                reject( {

                  error_message: "Finesse User Creation Error: An error occurred while creating the finesse user in the authenticate/sync finesse user component.",
                  error_detail: error
                } );

              }
            }
          }

          if ( updateUserPromise ) {
            await updateUserPromise; // Wait for the updateUser promise to resolve
            updateUserPromise = null; // Reset the promise
          }

          resolve( keycloakAuthToken );
        } else {

          resolve( finesseLoginResponse );
        }
      } catch ( er ) {

        reject( er );
      }
    } );
  }

  //Create a Finesse user during login.
  async createUser( userObject, token ) {

    let assignRole = [];
    let assignGroups = [];

    assignGroups = userObject.roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];


    return new Promise( async ( resolve, reject ) => {

      let URL = `${this.keycloakConfig[ "auth-server-url" ]}admin/realms/${this.keycloakConfig[ "realm" ]}/users`;

      let data = {

        username: userObject.username,
        firstName: userObject.firstName,
        lastName: userObject.lastName,
        enabled: true,
        credentials: [
          {
            type: "password",
            value: userObject.password,
            temporary: false,
          },
        ],
        attributes: {
          "user_name": `${userObject.loginName}`,
          "extension": `${userObject.extension}`
        },
        groups: assignGroups
      };

      let config = {

        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        data: data,

      };

      try {

        let newUser = await requestController.httpRequest( config, false );

        //Get the user id at time of creation
        let userLocation = newUser.headers.location;
        let userLocationSplit = userLocation.split( "/" );
        let userId = userLocationSplit[ userLocationSplit.length - 1 ];

        //Get list of all the roles in keycloak realm
        /* Storing all the realm roles in Global realmRoles list.If some role come from finesse which doesn't
        exist in realmRoles list then we call keycloak roles api again to update realmRoles list. */
        if ( userObject.roles != [] ) {

          if ( realmRoles.length > 0 ) {

            let check = checkForMissingRole( realmRoles, userObject.roles );

            if ( !check ) {

              realmRoles = await this.getRealmRoles( token );
            }

          } else {

            realmRoles = await this.getRealmRoles( token );
          }

          //checking whether role exist in realmRoles object array:
          for ( let role of realmRoles ) {

            userObject.roles.forEach( ( userRole ) => {

              if ( role.name == userRole.toLocaleLowerCase() ) {

                assignRole.push( {
                  id: role.id,
                  name: role.name,
                } );
              }
            } );
          }

          try {

            //assigning role to user
            let roleAssigned = await this.assignRoleToUser( userId, assignRole, token );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Role Assignment Error: An error occurred while assigning the role to the user in the Finesse user creation component.",
              error_detail: error
            } );
          }
        }


        let ciscoTeamId = userObject.group.id;

        //Check whether team of Agent already exists in CX Core or not
        let URL1 = `${this.keycloakConfig[ "ef-server-url" ]}team?ids=${ciscoTeamId}`;

        let config1 = {

          url: URL1,
          method: "get",
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "tenant-id": this.keycloakConfig[ "realm" ]
          }

        };

        let config2 = {

          method: "post",
          headers: {
            Accept: "application/json",
            "cache-control": "no-cache",
            "Content-Type": "application/json",
            "tenant-id": this.keycloakConfig[ "realm" ]
          },

        };


        try {

          let getAgentCXTeam = await requestController.httpRequest( config1, false );

          let createAgentCXTeam;

          //This means the team doesn't exist in CX Core. We need to create a team
          if ( getAgentCXTeam.data.length == 0 ) {

            //Setting URL to Create CX team of Agent
            let URL2 = `${this.keycloakConfig[ "ef-server-url" ]}team`;

            let data = {
              "team_Id": userObject.group.id,
              "team_name": userObject.group.name,
              "supervisor_Id": "",
              "source": "CISCO",
              "created_by": "1"
            }

            config2.url = URL2;
            config2.data = data;

            try {

              //Creating CX team of Agent
              createAgentCXTeam = await requestController.httpRequest( config2, false );

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Finesse Team Sync Error: Error occured while creating cx core team.",
                error_detail: error
              } );
            }

          }

          //First send the newly created user to CX DB.
          let URL3 = `${this.keycloakConfig[ "ef-server-url" ]}users/`;

          let data = {
            "id": userId,
            "username": userObject.username.toLocaleLowerCase(),
            "firstName": userObject.firstName,
            "lastName": userObject.lastName,
            "roles": userObject.roles
          }

          config2.url = URL3;
          config2.data = data;

          try {

            let sendSupUserToCX = await requestController.httpRequest( config2, false );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Finesse Team Sync Error: Error occured while sending user details to cx.",
              error_detail: error
            } );
          }

          //Assign Agent to a team
          let URL4 = `${this.keycloakConfig[ "ef-server-url" ]}team/${userObject.group.id}/member`;

          data = {
            "type": "agent",
            "usernames": [ userObject.username.toLocaleLowerCase() ]
          }

          config2.url = URL4;
          config2.data = data;

          try {

            //Assigning Agent to CX team
            let assignAgentToTeam = await requestController.httpRequest( config2, false );

          } catch ( er ) {

            let error = await errorService.handleError( er );

            reject( {

              error_message: "Finesse Team Sync Error: Error occured while assigning agent to cx core team.",
              error_detail: error
            } );
          }

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {

            error_message: "Finesse Team Sync Error: Error occured while fetching cx core team.",
            error_detail: error
          } );
        }



        if ( userObject.roles.includes( "supervisor" ) && userObject.supervisedGroups.length > 0 ) {

          for ( let supervisedGroup of userObject.supervisedGroups ) {

            let supervisorTeamId = supervisedGroup.id;

            //Check whether team of Supervisor already exists in CX Core or not
            let URL5 = `${this.keycloakConfig[ "ef-server-url" ]}team?ids=${supervisorTeamId}`;

            config1.url = URL5;

            try {

              let getSupervisorCXTeam = await requestController.httpRequest( config1, false );

              //This means the team doesn't exist in CX Core. We need to create a team
              if ( getSupervisorCXTeam.data.length == 0 ) {

                //Creating or Updating Supervisor team in CX Core.
                let URL6 = `${this.keycloakConfig[ "ef-server-url" ]}team`;

                let data = {
                  "team_Id": supervisorTeamId,
                  "team_name": supervisedGroup.name,
                  "supervisor_Id": userId,
                  "source": "CISCO",
                  "created_by": "1"
                }

                config2.method = 'post';
                config2.url = URL6;
                config2.data = data;

                try {

                  //Creating CX team of Supervisor
                  let createSupervisorCXTeam = await requestController.httpRequest( config2, false );

                } catch ( er ) {

                  let error = await errorService.handleError( er );

                  reject( {

                    error_message: "Finesse Team Sync Error: Error occured while creating cx core team.",
                    error_detail: error
                  } );
                }

              } else {

                console.log( getSupervisorCXTeam.data[ 0 ].supervisor_Id );

                //Adding this supervisor as Secondary Supervisor
                if ( getSupervisorCXTeam.data[ 0 ].supervisor_Id != null ) {

                  //Assign Secondary Supervisor to a team
                  let URL7 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}/member`;

                  data = {
                    "type": "secondary-supervisor",
                    "usernames": [ userObject.username.toLocaleLowerCase() ]
                  }

                  config2.method = 'post';
                  config2.url = URL7;
                  config2.data = data;

                  console.log( config2 );

                  try {

                    //Assigning Secondary Supervisor to CX team
                    let assignSecondarySupervisorToTeam = await requestController.httpRequest( config2, false );

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {

                      error_message: "Finesse Team Sync Error: Error occured while assigning secondary supervisor to cx core team.",
                      error_detail: error
                    } );
                  }

                } else {

                  //Check whether team of Supervisor already exists in CX Core or not
                  let URL8 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}`;

                  let data = {
                    "team_name": getSupervisorCXTeam.data[ 0 ].team_name,
                    "supervisor_Id": userId
                  }

                  config2.method = 'put';
                  config2.url = URL8;
                  config2.data = data;


                  try {

                    //Updating CX team of Supervisor
                    let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {

                      error_message: "Finesse Team Sync Error: Error occured while updating cx core team.",
                      error_detail: error
                    } );
                  }
                }

              }


            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Finesse Team Sync Error: Error occured while fetching cx core team.",
                error_detail: error
              } );
            }
          }

          resolve( newUser );

        } else {

          resolve( newUser );
        }

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "User Creation Error: An error occurred while creating the user in the Finesse user creation component.",
          error_detail: error
        } );
      }
    } );
  }

  //Check for changes in Finesse User on Each login.
  async updateUser( finObj, keycloakAdminToken, keycloakAuthToken, username, password ) {

    /* 
        Check for changes in user role, if user is removed from supervisor role then delete all its Permissions/Policies.
        If supervisor is added to user role then check for the groups it is supervising and create its permissions.
    
   
        Check for changes in user groups, if it is removed from one group as an agent and added to other group then remove
        user from old group and add to new group
   
   
        Check for teams user is supervising, if user is assigned new teams to supervise then create its permission/policy, if
        user is removed from supervising certain teams then remove its permissions from that team.
  */

    return new Promise( async ( resolve, reject ) => {

      let data = {};
      let userAttributes;

      let rolesToAdd;
      let rolesToRemove;
      let groupsToAdd;
      let groupsToRemove;
      let keycloakGroups;


      try {

        let rptToken = await this.getTokenRPT( username, password, keycloakAuthToken.access_token );
        let introspectToken = await this.getIntrospectToken( rptToken.access_token );

        let keyObj = {
          id: introspectToken.sub,
          username: introspectToken.username,
          firstName: introspectToken.given_name,
          lastName: introspectToken.family_name,
          roles: introspectToken.realm_access.roles,
          permittedResources: {
            Resources: introspectToken.authorization.permissions,
          }
        }

        //get user attributes to check its user_name and extension
        let URL = `${this.keycloakConfig[ "auth-server-url" ]}${this.keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${this.keycloakConfig[ "realm" ]}/users/${keyObj.id}`;

        let config = {

          method: "get",
          url: URL,
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${keycloakAdminToken.access_token}`,
          }
        };

        try {

          let userDataResponse = await requestController.httpRequest( config, false );
          userAttributes = userDataResponse.data.attributes;

        } catch ( err ) {

          let error = await errorService.handleError( err );

          reject( {

            error_message: "User Data Fetch Error: An error occurred while fetching user data during the Cisco user sync update process.",
            error_detail: error
          } );

        }

        //Comparing the basic info of Finesse User and Normal User.
        if ( ( finObj.username ).toLowerCase() != keyObj.username
          || finObj.firstName != keyObj.firstName
          || finObj.lastName != keyObj.lastName
          || ( userAttributes.user_name && finObj.loginName !== userAttributes.user_name[ 0 ] )
          || ( userAttributes.extension && finObj.extension !== userAttributes.extension[ 0 ] )
          || ( !userAttributes.user_name )
        ) {

          data = {
            username: ( finObj.username ).toLowerCase(),
            firstName: finObj.firstName,
            lastName: finObj.lastName,
            attributes: {
              "user_name": `${finObj.loginName}`,
              "extension": `${finObj.extension}`
            }
          };
        }

        if ( Object.keys( data ).length > 0 ) {


          let URL1 = `${this.keycloakConfig[ "auth-server-url" ]}${this.keycloakConfig[ "USERNAME_ADMIN" ]}/realms/${this.keycloakConfig[ "realm" ]}/users/${keyObj.id}`;

          config.url = URL1;
          config.method = 'put';
          config.data = data;

          try {

            await requestController.httpRequest( config, false );


          } catch ( err ) {

            let error = await errorService.handleError( err );

            reject( {

              error_message: "User Info Update Error: An error occurred while updating user information during the Cisco user sync process.",
              error_detail: error
            } );

          }

        }


        //Role to Add to keycloak user during Update process.
        //rolesToAdd = finObj.roles.filter( role => !keyObj.roles.includes( role ) );
        rolesToAdd = finObj.roles;

        //Role to Remove from keycloak user during Update process.
        let ignoreRoles = [ 'offline_access', 'uma_authorization' ];
        rolesToRemove = keyObj.roles.filter( role => (
          !finObj.roles.includes( role ) &&
          !ignoreRoles.includes( role ) &&
          role.indexOf( "default-roles" ) == -1 ) );

        //Updating group data in case it is not similar.
        let finesseGroups = finObj.roles.includes( "supervisor" ) ? [ "agents_permission", "senior_agents_permission" ] : [ "agents_permission" ];

        try {

          let token = keycloakAdminToken.access_token;

          let userGroups = await this.getKeycloakUserGroups( keyObj.id, token );

          keycloakGroups = userGroups.map( group => {
            return {
              id: group.id,
              name: group.name
            }
          } );

          //find if senior_agents_permission group is assigned to user already against an agent role.
          let isSeniorAgent = keycloakGroups.some( group => group.name == 'senior_agents_permission' );

          if ( isSeniorAgent && keyObj.roles.includes( 'agent' ) && !finesseGroups.includes( 'senior_agents_permission' ) ) {
            finesseGroups.push( 'senior_agents_permission' );
          }

          groupsToAdd = finesseGroups.filter( group => !keycloakGroups.find( keygroup => keygroup.name == group ) );
          groupsToRemove = keycloakGroups.filter( group => !finesseGroups.includes( group.name ) );

          //Adding and Removing Roles from Keycloak
          try {

            if ( rolesToAdd.length > 0 || rolesToRemove.length > 0 ) {
              const rolesPromises = [];

              if ( rolesToAdd.length > 0 ) {
                let addRolesPromise = this.addOrRemoveUserRole( keyObj.id, rolesToAdd, 'add', token );
                rolesPromises.push( addRolesPromise );
              }

              if ( rolesToRemove.length > 0 ) {
                let removeRolesPromise = this.addOrRemoveUserRole( keyObj.id, rolesToRemove, 'remove', token );
                rolesPromises.push( removeRolesPromise );
              }

              // Wait for all promises to complete before moving on
              await Promise.all( rolesPromises );
            }

            try {


              if ( groupsToAdd.length > 0 ) {

                //Fetching Ids of all the groups to add to current Keycloak User.
                groupsToAdd = await this.gettingGroupByGroupName( groupsToAdd, token );
                await this.addOrRemoveUserGroup( keyObj.id, groupsToAdd, 'add', token );
              }

              if ( groupsToRemove.length > 0 ) {

                await this.addOrRemoveUserGroup( keyObj.id, groupsToRemove, 'remove', token );
              }

              //Checking Agent Case first, if agent team in CX is not same as agent team in finesse then update it
              let userId = keyObj.id;
              let config1 = {

                method: "get",
                headers: {
                  Accept: "application/json",
                  "cache-control": "no-cache",
                  "Content-Type": "application/x-www-form-urlencoded",
                  "tenant-id": this.keycloakConfig[ "realm" ]
                }

              };

              //User Groups
              let URL2 = this.keycloakConfig[ "ef-server-url" ] + "team/user/" + userId;
              config1.url = URL2;

              let config2 = {

                method: "post",
                headers: {
                  Accept: "application/json",
                  "cache-control": "no-cache",
                  "Content-Type": "application/json",
                  "tenant-id": this.keycloakConfig[ "realm" ]
                },

              };

              try {

                let userTeams = await requestController.httpRequest( config1, true );

                const { userTeam, supervisedTeams } = userTeams.data;

                let supervisedTeamsFiltered = [];

                if ( supervisedTeams.length > 0 ) {

                  //Fetching list of all primary and seconday supervised teams of current user (Whether in CX or Cisco)
                  supervisedTeamsFiltered = supervisedTeams.filter( team => {
                    const isPrimarySupervisor = team.supervisor.username.toLocaleLowerCase() === username.toLocaleLowerCase();
                    const isSecondarySupervisor = team.secondarySupervisors.some( secSupervisor => secSupervisor.username.toLocaleLowerCase() === username.toLocaleLowerCase() );

                    return isPrimarySupervisor || isSecondarySupervisor;
                  } ).map( team => {
                    let type;
                    if ( team.supervisor.username.toLocaleLowerCase() === username.toLocaleLowerCase() ) {
                      type = 'supervisor';
                    } else if ( team.secondarySupervisors.some( secSupervisor => secSupervisor.username.toLocaleLowerCase() === username.toLocaleLowerCase() ) ) {
                      type = 'secondary supervisor';
                    }

                    return { teamId: team.teamId, teamName: team.teamName, type, source: team.source };
                  } );
                }

                //If Agent team in finesse is different from Agent Team in finesse
                if ( finObj.group.id !== userTeam.teamId ) {

                  //We have to both add agent to a team corresponding to Finesse and remove it from CX team.
                  //Removing agent from CX team first
                  let URL3 = `${this.keycloakConfig[ "ef-server-url" ]}team/${userTeam.teamId}/member?type=agent&usernames=${finObj.username.toLowerCase()}`;

                  config1.method = 'delete';
                  config1.url = URL3;

                  try {

                    let removeAgentFromCXTeam = await requestController.httpRequest( config1, true );

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {
                      error_message: "Finesse Team Sync Error: Error occurred while deleting user from a team in finesse user login (update).",
                      error_detail: error
                    } );

                  }

                  //Check whether team of Agent already exists in CX Core or not
                  let URL4 = `${this.keycloakConfig[ "ef-server-url" ]}team?ids=${finObj.group.id}`;

                  config1.method = 'get';
                  config1.url = URL4;


                  try {

                    let getAgentCXTeam = await requestController.httpRequest( config1, false );

                    let createAgentCXTeam;

                    //This means the team doesn't exist in CX Core. We need to create a team
                    if ( getAgentCXTeam.data.length == 0 ) {

                      //Setting URL to Create CX team of Agent
                      let URL5 = `${this.keycloakConfig[ "ef-server-url" ]}team`;

                      let data = {
                        "team_Id": finObj.group.id,
                        "team_name": finObj.group.name,
                        "supervisor_Id": "",
                        "source": "CISCO",
                        "created_by": "1"
                      }

                      config2.url = URL5;
                      config2.data = data;

                      try {

                        //Creating CX team of Agent
                        createAgentCXTeam = await requestController.httpRequest( config2, false );

                      } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                          error_message: "Finesse Team Sync Error: Error occured while creating cx core team to add user in finesse user login (update).",
                          error_detail: error
                        } );
                      }

                    }

                    //Assign Agent to a team
                    let URL6 = `${this.keycloakConfig[ "ef-server-url" ]}team/${finObj.group.id}/member`;

                    data = {
                      "type": "agent",
                      "usernames": [ finObj.username.toLowerCase() ]
                    }

                    config2.url = URL6;
                    config2.data = data;

                    try {

                      //Assigning Agent to CX team
                      let assignAgentToTeam = await requestController.httpRequest( config2, false );

                    } catch ( er ) {

                      let error = await errorService.handleError( er );

                      reject( {

                        error_message: "Finesse Team Sync Error: Error occured while assigning agent to cx core team in finesse user login (update).",
                        error_detail: error
                      } );
                    }

                  } catch ( er ) {

                    let error = await errorService.handleError( er );

                    reject( {
                      error_message: "Finesse Team Sync Error: Error occured while fetching user team to add user in finesse user login (update).",
                      error_detail: error
                    } );

                  }
                }

                //If no team is assigned to supervise to current user in Cisco, remove its all supervised teams from CX
                if ( !finObj.supervisedGroups && supervisedTeamsFiltered.length > 0 ) {

                  for ( let supervisedTeam of supervisedTeamsFiltered ) {

                    if ( supervisedTeam.source === 'CISCO' ) {

                      if ( supervisedTeam.type === 'secondary supervisor' ) {

                        //Removing user from Secondary Supervisor in CX Core
                        let URL13 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}/member?type=secondary-supervisor&usernames=${finObj.username.toLowerCase()}`;

                        config2.method = 'delete';
                        config2.url = URL13;

                        try {

                          //Updating CX team of Supervisor
                          let removeSecondarySupervisor = await requestController.httpRequest( config2, false );

                        } catch ( er ) {

                          let error = await errorService.handleError( er );

                          reject( {

                            error_message: "Finesse Team Sync Error: Error occured while updating cx core team to remove secondary supervisor.",
                            error_detail: error
                          } );
                        }


                      } else {

                        //Removing user from Supervising team in CX Core or not
                        let URL7 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}`;

                        let data = {
                          "team_name": supervisedTeam.teamName,
                          "supervisor_Id": null
                        }

                        config2.method = 'put';
                        config2.url = URL7;
                        config2.data = data;

                        try {

                          //Updating CX team of Supervisor
                          let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                        } catch ( er ) {

                          let error = await errorService.handleError( er );

                          reject( {

                            error_message: "Finesse Team Sync Error: Error occured while updating cx core team.",
                            error_detail: error
                          } );
                        }
                      }
                    }

                  }
                }

                //Supervisor Case. Filtering out teams to add and teams to remove from Supervisor
                //First check that We have supervised Groups in finesse
                if ( finObj.supervisedGroups ) {

                  let finesseSupervisedGroups = finObj.supervisedGroups;

                  // Fetching All the ids of CX Supervised Teams of current Supervisor
                  const teamIdsInSupervisedTeams = new Set( supervisedTeamsFiltered.map( team => team.teamId ) );

                  // Teams in which we need to add current user as Supervisor
                  const teamsToAddInCX = finesseSupervisedGroups.filter( item => !teamIdsInSupervisedTeams.has( item.id ) );

                  if ( teamsToAddInCX.length > 0 ) {

                    //Adding current user as supervisor in all the given teamsToAddInCX teams.
                    for ( let teamToAdd of teamsToAddInCX ) {

                      let supervisorTeamId = teamToAdd.id;

                      //Check whether team of Supervisor already exists in CX Core or not
                      let URL8 = `${this.keycloakConfig[ "ef-server-url" ]}team?ids=${supervisorTeamId}`;

                      config1.url = URL8;

                      try {

                        let getSupervisorCXTeam = await requestController.httpRequest( config1, false );

                        //This means the team doesn't exist in CX Core. We need to create a team
                        if ( getSupervisorCXTeam.data.length == 0 ) {

                          //Creating or Updating Supervisor team in CX Core.
                          let URL9 = `${this.keycloakConfig[ "ef-server-url" ]}team`;

                          let data = {
                            "team_Id": supervisorTeamId,
                            "team_name": teamToAdd.name,
                            "supervisor_Id": userId,
                            "source": "CISCO",
                            "created_by": "1"
                          }

                          config2.method = 'post';
                          config2.url = URL9;
                          config2.data = data;

                          try {

                            //Creating CX team of Supervisor
                            let createSupervisorCXTeam = await requestController.httpRequest( config2, false );

                          } catch ( er ) {

                            let error = await errorService.handleError( er );

                            reject( {

                              error_message: "Finesse Team Sync Error: Error occured while creating cx core team to add supervisor in finesse user login (update).",
                              error_detail: error
                            } );
                          }

                        } else {

                          //If the supervisor is already assigned to team, add current user as secondary supervisor.
                          if ( getSupervisorCXTeam.data[ 0 ].supervisor_Id != null ) {

                            //Assign Agent to a team
                            let URL10 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}/member`;

                            data = {
                              "type": "secondary-supervisor",
                              "usernames": [ finObj.username.toLowerCase() ]
                            }

                            config2.method = 'post';
                            config2.url = URL10;
                            config2.data = data;

                            try {

                              //Assigning Secondary Supervisor to CX team
                              let assignSecondarySupervisorToTeam = await requestController.httpRequest( config2, false );

                            } catch ( er ) {

                              let error = await errorService.handleError( er );

                              reject( {

                                error_message: "Finesse Team Sync Error: Error occured while assigning secondary supervisor to cx core team.",
                                error_detail: error
                              } );
                            }

                          } else {

                            //Adding current user as Supervisor to team
                            let URL11 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisorTeamId}`;

                            let data = {
                              "team_name": getSupervisorCXTeam.data[ 0 ].team_name,
                              "supervisor_Id": userId
                            }

                            config2.method = 'put';
                            config2.url = URL11;
                            config2.data = data;


                            try {

                              //Updating CX team of Supervisor
                              let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                            } catch ( er ) {

                              let error = await errorService.handleError( er );

                              reject( {

                                error_message: "Finesse Team Sync Error: Error occured while updating cx core team to add supervisor in finesse user login (update).",
                                error_detail: error
                              } );
                            }
                          }

                        }

                      } catch ( er ) {

                        let error = await errorService.handleError( er );

                        reject( {

                          error_message: "Finesse Team Sync Error: Error occured while fetching cx core team to add supervisor in finesse user login (update).",
                          error_detail: error
                        } );
                      }
                    }
                  }


                  // Fetching All the ids of Finesse Supervised Teams of current Supervisor
                  const idsInFinesseSupervisedGroups = new Set( finesseSupervisedGroups.map( item => item.id ) );

                  // Teams in which we need to remove current user as Supervisor
                  const teamsToRemoveFromCX = supervisedTeamsFiltered.filter( team => !idsInFinesseSupervisedGroups.has( team.teamId ) );

                  //Removing teams that Supervisor is not supervising anymore in finesse.
                  if ( teamsToRemoveFromCX.length > 0 ) {

                    for ( let supervisedTeam of teamsToRemoveFromCX ) {

                      //Only removing user from supervising teams that are from Cisco
                      if ( supervisedTeam.source === 'CISCO' ) {

                        if ( supervisedTeam.type === 'secondary supervisor' ) {

                          //Removing user from Secondary Supervisor in CX Core
                          let URL11 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}/member?type=secondary-supervisor&usernames=${finObj.username.toLowerCase()}`;

                          config2.method = 'delete';
                          config2.url = URL11;

                          try {

                            //Updating CX team of Supervisor
                            let removeSecondarySupervisor = await requestController.httpRequest( config2, false );

                          } catch ( er ) {

                            let error = await errorService.handleError( er );

                            reject( {

                              error_message: "Finesse Team Sync Error: Error occured while updating cx core team to remove secondary supervisor.",
                              error_detail: error
                            } );
                          }


                        } else {

                          //Removing user from Supervising team in CX Core
                          let URL12 = `${this.keycloakConfig[ "ef-server-url" ]}team/${supervisedTeam.teamId}`;

                          let data = {
                            "team_name": supervisedTeam.teamName,
                            "supervisor_Id": null
                          }

                          config2.method = 'put';
                          config2.url = URL12;
                          config2.data = data;

                          try {

                            //Updating CX team of Supervisor
                            let updateSupervisorCXTeam = await requestController.httpRequest( config2, false );

                          } catch ( er ) {

                            let error = await errorService.handleError( er );

                            reject( {

                              error_message: "Finesse Team Sync Error: Error occured while updating cx core team to remove supervisor.",
                              error_detail: error
                            } );
                          }
                        }

                      }

                    }

                  }

                }

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {
                  error_message: "Finesse Team Sync Error: Error occured while fetching user team in finesse user login (update).",
                  error_detail: error
                } );

              }
            } catch ( err ) {

              reject( err );
            }
          } catch ( err ) {

            reject( err );
          }
        } catch ( err ) {

          reject( err );
        }
      } catch ( err ) {

        reject( err );
      }

      resolve( [] );
    } );
  }

  //Sync implementation for teams along with its members (both create and update).
  async syncImplementation( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL ) {

    return new Promise( async ( resolve, reject ) => {

      try {

        let adminToken = await this.getAccessToken( this.keycloakConfig[ "USERNAME_ADMIN" ], this.keycloakConfig[ "PASSWORD_ADMIN" ] );
        let cxTeams = await ciscoSyncService.syncCiscoData( finesseAdministratorUsername, finesseAdministratorPassword, finesseURL, this.keycloakConfig, adminToken.access_token );

        resolve( cxTeams );

      } catch ( err ) {

        reject( err );
      }

    } );


    /*


    workflow:

    call Cisco teams API to get all the teams, call CX Teams List API to get teams from CX. Compare both and see is there is any additional Cisco Team which doesn't exist on CX or CX team with type "CISCO" that doesn't eixst in Cisco. Create Cisco teams that are missing on CX and delete/disable CX teams that are missing on Cisco side. Also check if team_name of any team is updated on Cisco side and update it on CX. After that, call team detail API to fetch all the members of each team one by one. Then call then "CX API to get members of specific team" to get the members on CX side of same team. Check if there is any member missing or additional member of CX side and make the members exactly as in Cisco side. If a member doesn't exist then create it in keycloak and add it in CX Team corresponding to Cisco. After that, check the data of each member by calling "Keycloak API to get member list" having attribute: "Cisco User" and compare it with users in "Cisco API to fetch user list". if any user is additional in Cisco list then create it in CX and add it in its subsequent list. If any user is additional on keycloak side then disable that user. Similary, update the info exactly to the Cisco user if there is any difference i.e change in role, firstname, lastname, loginname, extension, team, supervised teams "represented by <teams> in user respresentation". There should be both create and update scenarios based on existance or non-existance of team and its members (agents, supervisors)

    Requirements:

    All cisco apis require administrator credentials

    Cisco API to fetch all teams: https://uccx12-5p.ucce.ipcc:8445/finesse/api/Teams?nocache=1680864072911&bypassServerCache=true
    Cisco API to fetch team detail: https://uccx12-5p.ucce.ipcc:8445/finesse/api/Team/8
    Cisco API to fetch user detail: https://uccx12-5p.ucce.ipcc:8445/finesse/api/User/SE2606
    Cisco API to fetch user list: https://uccx12-5p.ucce.ipcc:8445/finesse/api/Users

    CX APIs:

    CX API to get all teams: https://cxtd-qa05.expertflow.com/unified-admin/team
    CX API to get members of specific team: https://cxtd-qa05.expertflow.com/unified-admin/team/{teamId}/member?limit=25&offset=0

    Keycloak APIs: 

    Keycloak API to get member list:  https://cxtd-qa05.expertflow.com/auth/admin/realms/{realm}/users
    Keycloak API to create user: https://cxtd-qa05.expertflow.com/auth/admin/realms/{realm}/users
    Keycloak API to get details of user: https://cxtd-qa05.expertflow.com/auth/admin/realms/{realm}/users/{user-id}
    Keycloak API to get roles of user: https://cxtd-qa05.expertflow.com/auth/admin/realms/{realm}/roles
    Keycloak API to assign roles to user: https://cxtd-qa05.expertflow.com/auth/admin/realms/{realm}/users/${userId}/role-mappings/realm

    */
  }

  async getCXUserDetails( user_name ) {

    return new Promise( async ( resolve, reject ) => {

      let token;
      let refresh_token;
      let error;
      let responseObject;
      user_name = ( user_name ).toLowerCase();

      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

      //this.keycloakConfig["auth-server-url"] +'realms
      let config = {

        method: "post",
        url: URL,
        headers: {
          Accept: "application/json",
          "cache-control": "no-cache",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          username: user_name,
          password: this.keycloakConfig[ "SYNC_AGENT_PASSWORD" ],
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: this.keycloakConfig.GRANT_TYPE,
        },

      };

      try {

        //  T.O.K.E.N   R.E.Q.U.E.S.T   # 1   ( P.E.R.M.I.S.S.I.O.N.S   N.O.T    I.N.C.L.U.D.E.D)
        let tokenResponse = await requestController.httpRequest( config, true );

        if ( tokenResponse.data.access_token ) {

          token = tokenResponse.data.access_token;

          //To fetch introspect token to handle errors.
          let config_introspect = { ...config };
          config_introspect.data.token = token;
          delete config_introspect.data.username;
          delete config_introspect.data.password;

          config_introspect.url = URL + "/introspect";

          try {

            let intro_token_response = await requestController.httpRequest( config_introspect, true );

            if ( Object.keys( intro_token_response.data ).length > 0 ) {

              try {

                let config1 = { ...config };
                config1.data.username = this.keycloakConfig.USERNAME_ADMIN;
                config1.data.password = this.keycloakConfig.PASSWORD_ADMIN;
                delete config1.data.token;

                config1.url = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig[ "realm" ] + "/protocol/openid-connect/token";

                let adminTokenResponse = await requestController.httpRequest( config1, true );

                if ( adminTokenResponse.data.access_token ) {

                  let admin_token = adminTokenResponse.data.access_token;

                  try {

                    config1.headers.Authorization = "Bearer " + admin_token;
                    config1.method = "get";
                    config1.url = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users?username=" + user_name + "&exact=true";
                    delete config1.data;

                    let getuserDetails = await requestController.httpRequest( config1, true );

                    if ( getuserDetails.data.length !== 0 ) {

                      responseObject = {

                        id: getuserDetails?.data[ 0 ]?.id,
                        firstName: getuserDetails?.data[ 0 ]?.firstName ? getuserDetails?.data[ 0 ]?.firstName : "",
                        lastName: getuserDetails?.data[ 0 ]?.lastName ? getuserDetails?.data[ 0 ]?.lastName : "",
                        username: getuserDetails?.data[ 0 ]?.username,
                        roles: ( 'realm_access' in intro_token_response?.data && 'roles' in intro_token_response?.data?.realm_access ) ? intro_token_response?.data?.realm_access?.roles : [],
                        realm: this.keycloakConfig[ "realm" ]
                      };

                      //Adding user custom attribute to our token object data.
                      if ( getuserDetails.data[ 0 ].attributes ) {

                        responseObject.attributes = getuserDetails.data[ 0 ].attributes;
                      } else {

                        responseObject.attributes = {};
                      }

                      delete config1.headers.Authorization;
                      delete config1.data;

                      //Fetching Groups data for each user.
                      try {

                        let teamData = await this.getUserSupervisedGroups( responseObject.id, admin_token, 'CX' );

                        //Check for Permission Groups assignment and roles assignment against them
                        const checkUserRoleAndPermissions = this.checkUserRoleAndPermissions( teamData, responseObject );

                        if ( checkUserRoleAndPermissions.error ) {

                          reject( {
                            error_message: "Token Generation Error: Failed to generate a user access token while fetching cx user details for qm.",
                            error_detail: {
                              status: 403,
                              reason: checkUserRoleAndPermissions.message
                            }
                          } );
                        }

                        delete teamData.permissionGroups;

                        responseObject.userTeam = teamData.userTeam;
                        responseObject.supervisedTeams = teamData.supervisedTeams;

                      } catch ( er ) {

                        reject( er );
                      }

                    } else {

                      reject( {
                        error_message: "User Details Fetch Error: Could not retrieve user information while fetching cx user details for qm.",
                        error_detail: {
                          status: 404,
                          reason: `User Not Found: The specified username ${user_name} does not exist.`
                        }
                      } );

                    }


                  } catch ( er ) {

                    error = await errorService.handleError( er );

                    reject( {
                      error_message: "Admin Token Generation Error: Failed to generate an admin access token while fetching cx user details for qm.",
                      error_detail: error
                    } );
                  }
                }

              } catch ( er ) {

                error = await errorService.handleError( er );

                reject( {
                  error_message: "Admin Token Generation Error: Failed to generate an admin access token while fetching cx user details for qm.",
                  error_detail: error
                } );

              }
            }

            config = {

              method: "post",
              url: URL,
              headers: {
                Accept: "application/json",
                "cache-control": "no-cache",
                "Content-Type": "application/x-www-form-urlencoded",
              },
              data: {
                username: user_name,
                password: this.keycloakConfig[ "SYNC_AGENT_PASSWORD" ],
                client_id: this.keycloakConfig.CLIENT_ID,
                client_secret: this.keycloakConfig.credentials.secret,
                grant_type: this.keycloakConfig.GRANT_TYPE,
              },

            };

            config.data.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket";
            config.data.audience = this.keycloakConfig.CLIENT_ID;
            config.headers.Authorization = "Bearer " + token;

            //  T.O.K.E.N   R.E.Q.U.E.S.T   # 2   (A.C.C.E.S.S   T.O.K.E.N   W.I.T.H   P.E.R.M.I.S.S.I.O.N.S)
            try {

              let rptResponse = await requestController.httpRequest( config, true );

              if ( rptResponse.data.access_token ) {
                token = rptResponse.data.access_token;
                refresh_token = rptResponse.data.refresh_token;

                let userToken = token;
                config.data.grant_type = this.keycloakConfig.GRANT_TYPE;
                config.data.token = token;
                URL = URL + "/introspect";
                config.url = URL;

                //  T.O.K.E.N   R.E.Q.U.E.S.T   # 3   (A.C.C.E.S.S   T.O.K.E.N   I.N.T.R.O.S.P.E.C.T.I.O.N)
                try {

                  let intrsopectionResponse = await requestController.httpRequest( config, true );
                  intrsopectionResponse.data.access_token = token;

                  responseObject.permittedResources = {
                    Resources: ( intrsopectionResponse.data.authorization.permissions.length > 0 ) ? intrsopectionResponse.data.authorization.permissions : []
                  }

                  //  T.O.K.E.N   R.E.Q.U.E.S.T   # 4   ( A.D.M.I.N.  T.O.K.E.N)

                  let finalObject = {

                    keycloak_User: responseObject,

                  };

                  resolve( finalObject );

                } catch ( er ) {

                  error = await errorService.handleError( er );

                  reject( {
                    error_message: "Introspect Token Generation Error: Failed to generate an introspection token while fetching cx user details for qm.",
                    error_detail: error
                  } );

                }

              }

            } catch ( er ) {

              error = await errorService.handleError( er );

              reject( {
                error_message: "Rpt Token Fetch Error: Could not fetch the refresh token. Please ensure the user has the necessary roles, permissions, and groups" +
                  ". e.g: agent user must be assigned agent role, agents_permission group & all required permissions are created" +
                  ". every user must be assigned one team, if user is not part of any team then assign default team to User.",
                error_detail: {
                  "status": 403,
                  "reason": "Missing role, team, or permissions to log in. Please check with your administrator."
                }
              } );

            }



          } catch ( er ) {

            error = await errorService.handleError( er );

            reject( {
              error_message: "Token Generation Error: Failed to generate a user access introspect token for qm.",
              error_detail: error
            } );

          }
        }

      } catch ( er ) {

        error = await errorService.handleError( er );

        reject( {
          error_message: "Token Generation Error: Failed to generate a user access token for qm.",
          error_detail: error
        } );

      }
    } );

  }

  async createTeamsAndMembers() {

  }

  async updateTeamsAndMembers() {

  }

  async checkPasswordUpdate( adminToken, userName, password ) {

    return new Promise( async ( resolve, reject ) => {

      let passwordUpdate = false;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users?search=" + userName + "&briefRepresentation=false&exact=true"

      let config = {
        method: "get",
        url: URL,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken}`,
        }
      };

      try {

        //First check if the user exists or not in Keycloak, search user by username in Keycloak.
        let userResponse = await requestController.httpRequest( config, false );

        if ( userResponse.data.length > 0 ) {

          //Since user exists against username, now generate its access-token.
          /*
            If the access token is not generated, it means that password on
            Keycloak side is not valid and should be updated.
          */
          try {

            let tokenResponse = await this.getAccessToken( userName, password );

            if ( tokenResponse.access_token ) {

              resolve( [] );
            }

          } catch ( er ) {

            if ( er.error_detail.status == 401 ) {

              passwordUpdate = true;

            } else {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "User Access Token Generation Error: An error occurred while generating the user access token in the check updated password component.",
                error_detail: error
              } );
            }

          } finally {

            if ( passwordUpdate ) {

              let userId = userResponse.data[ 0 ].id;

              //API URL used to update the password.
              let URL2 = this.keycloakConfig[ "auth-server-url" ] + "admin/realms/" + this.keycloakConfig[ "realm" ] + "/users/" + userId + "/reset-password"

              let data = {
                "temporary": false,
                "type": "password",
                "value": password
              }

              let config2 = {
                method: "put",
                url: URL2,
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${adminToken}`,
                },
                data: data
              };

              try {

                //Sending request to Update Password.
                await requestController.httpRequest( config2, false );

              } catch ( er ) {

                let error = await errorService.handleError( er );

                reject( {

                  error_message: "Password Update Error: An error occurred while updating the password of the user in the check updated password component.",
                  error_detail: error
                } );

              }

            }

          }


        }

        resolve( [] );

      } catch ( er ) {

        let error = await errorService.handleError( er );

        reject( {

          error_message: "User Search Error: An error occurred while searching for the user by username in the check updated password component.",
          error_detail: error
        } );
      }
    } );
  }


  async generateAccessTokenFromRefreshToken( refreshToken ) {
    return new Promise( async ( resolve, reject ) => {
      let accessToken;
      let URL = this.keycloakConfig[ "auth-server-url" ] + "realms/" + this.keycloakConfig.realm + "/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: this.keycloakConfig.CLIENT_ID,
          client_secret: this.keycloakConfig.credentials.secret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        },
      };

      try {
        let refreshTokenResponse = await requestController.httpRequest( config, true );

        let accessToken = refreshTokenResponse.data.access_token;
        resolve( {
          status: 200,
          access_token: accessToken,
        } );
      } catch ( error ) {
        if ( error.response ) {
          if ( error.response.data.error_description == "Token is not active" ) {
            error.response.data.error_description = "Refresh Token Expired: The refresh token has expired. Please log in again.";
          }

          reject( {
            status: error.response.status,
            message: `${error.response.data.error_description}`,
          } );
        } else {
          reject( { message: error.message } );
        }
      }
    } );
  }

  // !-------------- Multitenancy -----------------!

  async createRealmAsTenant( tenantName, realmDataString, authzConfigDataString, keycloakConfig ) {

    return new Promise( async ( resolve, reject ) => {

      let realmData;
      let authzConfigData;


      try {

        realmData = JSON.parse( realmDataString );

      } catch ( parseError ) {

        if ( parseError instanceof SyntaxError ) {

          reject( {
            "error_message": "Error occurred while parsing Realm file during Tenant creation process.",
            "error_detail": {
              "status": 400,
              "reason": `Invalid JSON in realm configuration file: ${parseError.message} `
            }
          } );
        }

        reject( {
          "error_message": "Error occurred while parsing Realm file during Tenant creation process.",
          "error_detail": {
            "status": 500,
            "reason": `Error parsing realm configuration file: ${parseError.message}`
          }
        } );
      }

      if ( Object.keys( realmData ).length < 1 ) {

        reject( {
          errorStatus: 400,
          errorMessage: `Received no realm data to import while creating tenant. Please send the correct realm data from realm file`
        } );
      }

      let realmImportSuccessful = false;
      let mainMessage = "";

      let accessToken;
      let URL = keycloakConfig[ "auth-server-url" ] + "realms/master/protocol/openid-connect/token";

      let config = {
        method: "post",
        url: URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: {
          client_id: "admin-cli",
          grant_type: "password",
          username: keycloakConfig[ "MASTER_USERNAME" ],
          password: keycloakConfig[ "MASTER_PASSWORD" ]
        },
      };

      try {

        let adminAccessToken = await requestController.httpRequest( config, true );

        accessToken = adminAccessToken.data.access_token;

        let createRealmUrl = keycloakConfig[ "auth-server-url" ] + 'admin/realms';

        // 1. Read the realm configuration JSON file
        console.log( `Reading realm configuration from provided realm data.` );

        realmData.id = tenantName;
        realmData.realm = tenantName;


        let config1 = {

          method: "post",
          url: createRealmUrl,
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${accessToken}`
          },
          data: realmData
        };

        try {

          let realmCreation = await requestController.httpRequest( config1, false );

          if ( realmCreation.status === 201 ) {

            realmImportSuccessful = true;
            mainMessage = `Realm '${tenantName}' imported successfully!\n`;

          }

          console.log( mainMessage );

          // --- Authorization Settings Import (if applicable) ---
          if ( realmImportSuccessful && authzConfigDataString ) {

            let targetClientIdForAuthz = 'cim';

            console.log( `Proceeding to import authorization settings for client '${targetClientIdForAuthz}' in realm '${tenantName}'.` );
            let clientUuid = '';

            try {

              // 4. Get the internal UUID of the target client
              console.log( `Fetching UUID for client '${targetClientIdForAuthz}' in realm '${tenantName}'...` );
              const getClientUrl = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${tenantName}/clients`;

              let config2 = {

                method: "get",
                url: getClientUrl,
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": `Bearer ${accessToken}`
                },
                params: {
                  clientId: targetClientIdForAuthz,
                  search: true
                }
              };

              const clientSearchResponse = await requestController.httpRequest( config2, false );

              if ( clientSearchResponse.data && clientSearchResponse.data.length > 0 ) {

                // Filter to be sure, as Keycloak might return multiple if clientId is a substring without exact match flag
                const foundClient = clientSearchResponse?.data?.find( client => client?.clientId === targetClientIdForAuthz );

                if ( foundClient ) {

                  clientUuid = foundClient.id;
                  console.log( `Found client UUID: ${clientUuid}` );
                } else {

                  throw new Error( `Client with clientId '${targetClientIdForAuthz}' not found in realm '${tenantName}' after filtering.` );
                }
              } else {
                throw new Error( `Client with clientId '${targetClientIdForAuthz}' not found in realm '${tenantName}'. Response: ${JSON.stringify( clientSearchResponse.data )}` );
              }


              // 6. Make the API call to Keycloak to import/update authorization settings
              console.log( `Importing authorization settings for client UUID '${clientUuid}'...` );

              try {

                authzConfigData = JSON.parse( authzConfigDataString );

              } catch ( parseError ) {

                if ( parseError instanceof SyntaxError ) {

                  reject( {
                    "error_message": `Error occurred while parsing Authz file while importing Permissions/Policies in ${targetClientIdForAuthz} during Tenant creation process.`,
                    "error_detail": {
                      "status": 400,
                      "reason": `Invalid JSON in authz configuration file: ${parseError.message} `
                    }
                  } );
                }

                reject( {
                  "error_message": `Error occurred while parsing Authz file while importing Permissions/Policies in ${targetClientIdForAuthz} during Tenant creation process.`,
                  "error_detail": {
                    "status": 500,
                    "reason": `Error parsing JSON in authz configuration file: ${parseError.message}`
                  }
                } );
              }

              if ( Object.keys( authzConfigData ).length < 1 ) {

                reject( {
                  errorStatus: 400,
                  errorMessage: `Received no authorization data to import while creating tenant. Please send the correct authorization data from authz file`
                } );
              }

              const importAuthzUrl = `${keycloakConfig[ "auth-server-url" ]}admin/realms/${tenantName}/clients/${clientUuid}/authz/resource-server/import`;

              let config3 = {

                method: "post",
                url: importAuthzUrl,
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": `Bearer ${accessToken}`
                },
                data: authzConfigData
              };

              const authzResponse = await requestController.httpRequest( config3, false );

              try {

                // Keycloak typically returns 204 No Content for successful PUT on authz settings
                if ( authzResponse.status === 204 || authzResponse.status === 200 || authzResponse.status === 201 ) {

                  const authzSuccessMessage = ` Authorization settings for client '${targetClientIdForAuthz}' (UUID: ${clientUuid}) imported successfully into realm '${tenantName}'.`;

                  console.log( authzSuccessMessage );
                  mainMessage += `${authzSuccessMessage}`;

                  resolve( {

                    status: 201,
                    message: mainMessage
                  } );

                } else {

                  const authzWarningMessage = ` Authorization settings import for client '${targetClientIdForAuthz}' may have completed with status: ${authzResponse.status}. Response: ${JSON.stringify( authzResponse.data )}`;
                  console.warn( authzWarningMessage );
                  mainMessage += `${authzWarningMessage}`;

                  resolve( {

                    status: 201,
                    message: mainMessage
                  } );
                }

              } catch ( er ) {

                console.error( `Error importing authorization settings for client '${targetClientIdForAuthz}':` );

                if ( er?.response ) {

                  console.error( 'Keycloak API Error Status (Authz Import):', er?.response?.status );
                  console.error( 'Keycloak API Error Data (Authz Import):', JSON.stringify( er?.response?.data, null, 2 ) );

                } else if ( er?.request ) {

                  console.error( 'No response received from Keycloak (Authz Import):', er.request );


                } else {

                  console.error( 'Error during authz import request setup or client lookup:', er?.message );
                }

                let error = await errorService.handleError( er );

                reject( {
                  error_message: "Realm Creation Error: Error while importing permissions/policies in newly created tenant in keycloak from authz file.",
                  error_detail: error
                } );

              }

            } catch ( er ) {

              let error = await errorService.handleError( er );

              reject( {

                error_message: "Realm Creation Error: Error occurred while fetching list of clients of newly created tenant",
                error_detail: error
              } );

            }
          }

        } catch ( er ) {

          let error = await errorService.handleError( er );

          reject( {
            error_message: "Realm Creation Error: Error while creating realm in keycloak from realm-file.",
            error_detail: error
          } );

        }

      } catch ( error ) {

        if ( error.response ) {

          if ( error.response.data.error_description == "Token is not active" ) {
            error.response.data.error_description = "Refresh Token Expired: The refresh token has expired. Please log in again.";
          }

          reject( {
            status: error.response.status,
            message: `${error.response.data.error_description}`,
          } );
        } else {

          reject( { message: error.message } );
        }

      }
    } );

  }

  // !-------------- Multitenancy End -----------------!

  //start
  startUserMonitoring = async ( { pollingInterval }, callback ) => {

    return new Promise( ( resolve, reject ) => {

      if ( !this.keycloakConfig[ "auth-server-url" ] || !this.keycloakConfig[ "realm" ] ) {
        reject( {
          error_message: "Configuration Error: baseUrl and realm are required in config.",
          error_detail: "Missing required configuration parameters"
        } );
        return;
      }

      const polling = pollingInterval || DEFAULT_POLLING_INTERVAL;
      let lastCheckTime = Date.now();
      let monitoringInterval;

      try {

        monitoringInterval = setInterval( async () => {

          try {

            const events = await fetchAdminEvents( this.keycloakConfig[ "auth-server-url" ], this.keycloakConfig[ "realm" ], this.keycloakConfig[ "USERNAME_ADMIN" ], this.keycloakConfig[ "PASSWORD_ADMIN" ] );
            const newEvents = getNewEvents( events );

            newEvents.forEach( event => {

              const userData = parseUserData( event.representation );

              if ( userData ) {

                callback( {
                  time: event.time,
                  realmId: event.realmId,
                  authDetails: event.authDetails,
                  operationType: event.operationType,
                  resourceType: event.resourceType,
                  resourcePath: event.resourcePath,
                  representation: userData
                } );

              }

            } );

            lastCheckTime = Date.now();

          } catch ( error ) {

            console.error( 'Error in monitoring loop:', error );
          }

        }, polling );

        // Return the stop function
        resolve( () => {

          clearInterval( monitoringInterval );
          previousEvents = [];
          isFirstRun = true;

          return {
            message: "Monitoring stopped successfully"
          };

        } );

      } catch ( error ) {

        reject( {
          error_message: "Monitoring Start Error: Failed to start user monitoring.",
          error_detail: error
        } );
      }
    } );
  };

}

function checkForMissingRole( keycloakRealmRoles, requiredRoles ) {

  // Convert the object names to a Set for faster lookup
  const rolesNamesSet = new Set( keycloakRealmRoles.map( role => role.name ) );

  // Use the some method to check if at least one role is missing
  const isMissing = requiredRoles.some( role => !rolesNamesSet.has( role ) );

  return !isMissing;
}

let parseUserData = ( representation ) => {

  try {

    return JSON.parse( representation );
  } catch ( error ) {

    return null;
  }
};

let extractUserId = ( resourcePath ) => {

  return resourcePath.split( '/' )[ 1 ];
};

let getNewEvents = ( events ) => {

  if ( isFirstRun ) {
    previousEvents = events;
    isFirstRun = false;
    return events;
  }

  // If there are new events and we have previous events to compare against
  if ( events.length > 0 && previousEvents.length > 0 ) {

    // Get the timestamp of our most recent stored event
    const lastStoredEventTime = previousEvents[ 0 ].time;

    // Filter only events that are newer than our last stored event
    const genuinelyNewEvents = events.filter( event => event.time > lastStoredEventTime );

    if ( genuinelyNewEvents.length > 0 ) {

      previousEvents = genuinelyNewEvents;
      return genuinelyNewEvents;
    }
  }

  // If no new events, return previous events to maintain state
  return previousEvents;
};

let fetchAdminEvents = ( baseUrl, realm, adminUsername, adminPassword ) => {

  return new Promise( async ( resolve, reject ) => {

    let keycloakAdminToken;

    try {

      //Fetching admin token, we pass it in our "Create User" API for authorization
      keycloakAdminToken = await this.getAccessToken( adminUsername, adminPassword );

    } catch ( err ) {

      let error = await errorService.handleError( err );

      return ( {

        error_message: "Keycloak Admin Token Fetch Error: An error occurred while fetching the keycloak admin token in the Admin Events component.",
        error_detail: error
      } );

    }

    const url = `${baseUrl}admin/realms/${realm}/admin-events`;

    const config = {
      method: "get",
      url: url,
      headers: {
        Authorization: `Bearer ${keycloakAdminToken.access_token}`,
        Accept: "application/json",
        "cache-control": "no-cache"
      },
      params: {
        operationTypes: 'CREATE',
        resourceTypes: 'USER'
      }
    };

    try {

      const response = await requestController.httpRequest( config, false );

      resolve( response.data );

    } catch ( error ) {

      reject( {
        error_message: "Admin Events Fetch Error: Failed to fetch admin events.",
        error_detail: error
      } );
    }
  } );
};

function validateUser( userData ) {
  let schema = Joi.object( {
    username: Joi.string().min( 1 ).max( 255 ).required(),
    password: Joi.string().min( 1 ).max( 255 ).required(),
    token: Joi.string().required(),
    userRoles: Joi.array().items( Joi.string() ).allow( null ),
  } );

  return schema.validate( userData );
}

module.exports = KeycloakService;