// Doc:
// - https://github.com/konnectors/edf/blob/master/src/index.js
// - https://github.com/konnectors/libs/blob/master/packages/cozy-konnector-libs/src/libs/CookieKonnector.js
// - https://www.npmjs.com/package/request-promise

const {
  CookieKonnector,
  requestFactory,
  signin,
  scrape,
  saveBills,
  log,
  utils,
  errors
} = require('cozy-konnector-libs')
const urlEncoder = require('querystring')

const VENDOR = 'carrefour'
const baseUrl = 'https://www.carrefour.fr'
const myAccountBaseUrl = 'https://moncompte.carrefour.fr'
const gotoUrl =
  myAccountBaseUrl.replace('s://', '://') +
  '/iam/oauth2/CarrefourConnect/authorize?' +
  urlEncoder.encode({
    response_type: 'code',
    client_id: 'carrefour_onecarrefour_web',
    scope:
      'openid iam register-' +
      Buffer.from(`${myAccountBaseUrl}/mon-compte/inscription`).toString(
        'base64'
      ),
    redirect_uri: 'https://www.carrefour.fr/login/check'
  })

class CarrefourConnector extends CookieKonnector {
  // Initialize the HTML request options used by this konnector
  initRequestHtml() {
    this.requestHtml = this.requestFactory({
      // The debug mode shows all the details about HTTP requests and responses. Very useful for
      // debugging but very verbose. This is why it is set to false by default
      debug: false,
      // Activates [cheerio](https://cheerio.js.org/) parsing on each page
      cheerio: false,
      // If cheerio is activated do not forget to deactivate json parsing (which is activated by
      // default in cozy-konnector-libs)
      json: true,
      // This allows request-promise to keep cookies between requests
      jar: this._jar._jar,
      // Activate full response to get status code
      resolveWithFullResponse: true
    })
  }

  async authenticateRequest(url, options) {
    try {
      return await this.requestHtml(url, options)
    } catch (err) {
      log('error', err.message)
      switch (err.statusCode) {
        case 403:
          throw new Error(errors.CHALLENGE_ASKED)
        default:
          throw new Error(errors.LOGIN_FAILED)
      }
    }
  }

  async finalizeAuthentication(id) {
    const userData = await this.authenticateRequest(
      `${myAccountBaseUrl}/iam/json/carrefourconnect/users/${id}`,
      {
        qs: {
          realm: '/CarrefourConnect'
        }
      }
    )

    const getValidate = await this.authenticateRequest(
      `${myAccountBaseUrl}/iam/json/users`,
      {
        method: 'POST',
        qs: {
          _action: 'validateGoto'
        },
        body: {
          goto: gotoUrl
        }
      }
    )

    await this.authenticateRequest(getValidate.body.successURL)
  }

  // Test if a session stored in the cookies can be used to connect
  async testSession() {
    try {
      const getId = await this.requestHtml(
        `${myAccountBaseUrl}/iam/json/users`,
        {
          method: 'POST',
          qs: {
            _action: 'idFromSession',
            realm: '/CarrefourConnect'
          }
        }
      )

      await this.finalizeAuthentication(getId.body.id)

      return true
    } catch (err) {
      log('debug', err.message)
      return false
    }
  }

  // Authentication process
  async authenticate(login, password) {
    await this.authenticateRequest('https://www.carrefour.fr/mon-compte/login')
    const getAuthId = await this.authenticateRequest(
      `${myAccountBaseUrl}/iam/json/authenticate`,
      {
        method: 'POST',
        qs: {
          realm: '/CarrefourConnect',
          goto: gotoUrl
        }
      }
    )

    getAuthId.body.callbacks[0].input[0].value = login
    getAuthId.body.callbacks[1].input[0].value = password
    const getTokenId = await this.authenticateRequest(
      `${myAccountBaseUrl}/iam/json/authenticate`,
      {
        method: 'POST',
        qs: {
          realm: '/CarrefourConnect'
        },
        body: {
          authId: getAuthId.body.authId,
          template: getAuthId.body.template,
          stage: getAuthId.body.stage,
          header: getAuthId.body.header,
          callbacks: getAuthId.body.callbacks
        }
      }
    )

    this._jar._jar.setCookieSync(
      `c4iamsecuretk=${getTokenId.body.tokenId}`,
      myAccountBaseUrl,
      {}
    )
    const getId = await this.authenticateRequest(
      `${myAccountBaseUrl}/iam/json/users`,
      {
        method: 'POST',
        qs: {
          _action: 'idFromSession',
          realm: '/CarrefourConnect'
        }
      }
    )

    await this.finalizeAuthentication(getId.body.id)
  }

  // Main function
  async fetch(fields) {
    // Initialize the request
    this.initRequestHtml()
    // Check if the stored session can be used
    if (!(await this.testSession())) {
      log('info', 'No correct session found, authenticating...')
      await this.authenticate(fields.login, fields.password)
      log('info', 'Successfully logged in')
    }
  }
}

// Create and run the konnector
const connector = new CarrefourConnector()
connector.run()
