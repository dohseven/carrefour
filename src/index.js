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
  // Initialize the HTML request options for the authentication phase
  initAuthenticationRequestHtml() {
    this.authenticationRequestHtml = this.requestFactory({
      debug: false,
      cheerio: false,
      json: true,
      jar: this._jar._jar,
      resolveWithFullResponse: true
    })
  }

  // Initialize the HTML request options for the retrieval phase
  initRequestHtml() {
    this.requestHtml = this.requestFactory({
      debug: false,
      cheerio: true,
      json: false,
      jar: this._jar._jar
    })
  }

  async authenticateRequest(url, options) {
    try {
      let optionsWithHeader = (options ? options : {})
      optionsWithHeader.headers = {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept-API-Version': 'protocol=1.0,resource=2.0',
        'TE': 'Trailers'
      }
      return await this.authenticationRequestHtml(url, optionsWithHeader)
    } catch (err) {
      checkError(err)
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
      const getId = await this.authenticationRequestHtml(
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

  async getDocumentsList() {
    try {
      return await this.requestHtml(`${baseUrl}/mon-compte/commandes`)
    } catch (err) {
      checkError(err)
    }
  }

  async parseDocuments(ordersList) {
    log('debug', ordersList)
    const orders = scrape(
      ordersList,
      {
        orders: {
          sel: 'orders-delivered'
        }
      },
      '#order-summary'
    )
    log('debug', orders)
  }

  // Main function
  async fetch(fields) {
    // Initialize the requests
    this.initAuthenticationRequestHtml()
    this.initRequestHtml()
    // Check if the stored session can be used
    if (!(await this.testSession())) {
      log('info', 'No correct session found, authenticating...')
      await this.authenticate(fields.login, fields.password)
      log('info', 'Successfully logged in')
    }
    // Retrieve the orders list
    const docs = this.getDocumentsList()
    this.parseDocuments(docs)
  }
}

// Create and run the konnector
const connector = new CarrefourConnector()
connector.run()

function checkError(err) {
  log('error', err.message)
  switch (err.statusCode) {
    case 403:
      throw new Error(errors.CHALLENGE_ASKED)
    default:
      throw new Error(errors.LOGIN_FAILED)
  }
}
