import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';
import uri from 'url';

const VERSION = '2.1';
const AUTHORIZATION_URL = 'https://access.line.me/oauth2/v{VERSION}/authorize';
const TOKEN_URL = 'https://api.line.me/oauth2/v{VERSION}/token';
const PROFILE_URL = 'https://api.line.me/v2/profile';
const DEFAULT_SCOPE = 'profile';

export default class LineTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {

    if (!_options.clientID) {
      throw new Error('clientID must be set');
    }

    if (!_options.clientSecret) {
      throw new Error('clientSecret must be set');
    }


    let options = _options || {};
    let verify = _verify;

    options.version = options.version || VERSION;
    options.authorizationURL = options.authorizationURL || AUTHORIZATION_URL.replace('{VERSION}', options.version);
    options.tokenURL = options.tokenURL || TOKEN_URL.replace('{VERSION}', options.version);
    options.scope = options.scope || DEFAULT_SCOPE;
    options.state = true;
    options.botPrompt = null;

    super(options, verify);

    this.name = 'line-token';

    this._profileURL = options.profileURL || PROFILE_URL;
    this._clientId = options.clientID;
    this._clientSecret = options.clientSecret;
    this._botPrompt = options.botPrompt;
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Authenticate request by delegating to Line using OAuth.
   * @param {Object} req
   */
  authenticate(req, options) {
    // Following the link back to the application is interpreted as an authentication failure
    if (req.query && req.query.denied) return this.fail();

    let token = (req.body && req.body[this._oauthTokenField]) || (req.query && req.query[this._oauthTokenField]);
    let tokenSecret = (req.body && req.body[this._oauthTokenSecretField]) || (req.query && req.query[this._oauthTokenSecretField]);
    let userId = (req.body && req.body[this._userIdField]) || (req.query && req.query[this._userIdField]) || (token && token.split('-')[0]);

    if (!token) return this.fail({message: `You should provide ${this._oauthTokenField} and ${this._oauthTokenSecretField}`});

    this._loadUserProfile(token, tokenSecret, {user_id: userId}, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, token, tokenSecret, profile, verified);
      } else {
        this._verify(token, tokenSecret, profile, verified);
      }
    });
  }

  /**
   * Retrieve user profile from LINE.
   * @param {String} token
   * @param {String} tokenSecret
   * @param {Object} params
   * @param {Function} done
   */
  userProfile(token, tokenSecret, params, done) {
    let url = uri.format(uri.parse(this._profileURL));

    this._oauth2.get(url, accessToken, function (err, body, res) {
      if (err) {
        return done(new InternalOAuthError('Failed to fetch user profile', err));
      }

      try {
        let json = JSON.parse(body);

        let profile = {provider: 'line'};
        profile.id = json.userId;
        profile.displayName = json.displayName;
        profile.pictureUrl = json.pictureUrl;

        profile._raw = body;

        done(null, profile);
      } catch (e) {
        done(e);
      }
    });
  }
}
