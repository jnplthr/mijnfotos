// Note: no need to bundle <aws-sdk>, it's provided by Lambda
const AWS = require('aws-sdk')
const async = require('async')
const cloudfront = require('aws-cloudfront-sign')

// --------------
// Lambda function parameters, as environment variables
// --------------

const CONFIG_KEYS = {
  websiteDomain: 'WEBSITE_DOMAIN',
  sessionDuration: 'SESSION_DURATION',
  cloudFrontKeypairId: 'CLOUDFRONT_KEYPAIR_ID',
  cloudFrontPrivateKey: 'ENCRYPTED_CLOUDFRONT_PRIVATE_KEY'
}

// --------------
// Main function exported to Lambda
// Checks username/password against the <htaccess> entries
// --------------

exports.handler = (event, context, callback) => {
  console.log(event)
  // get and decrypt config values
  async.mapValues(CONFIG_KEYS, getConfigValue, function (err, config) {
    if (err) {
      callback(null, {
        statusCode: 500,
        body: 'Server error'
      })
    } else {
      console.log('Generating signed cookies')
      var responseHeaders = cookiesHeaders(config)
      callback(null, {
        statusCode: 200,
        body: JSON.stringify(responseHeaders),
        headers: responseHeaders
      })
    }
  })
}

// --------------
// Returns the corresponding config value
// After decrypting it with KMS if required
// --------------

function getConfigValue (configName, target, done) {
  if (/^ENCRYPTED/.test(configName)) {
    const kms = new AWS.KMS()
    const encrypted = process.env[configName]
    kms.decrypt({ CiphertextBlob: new Buffer(encrypted, 'base64') }, (err, data) => {
      if (err) done(err)
      else done(null, data.Plaintext.toString('ascii'))
    })
  } else {
    done(null, process.env[configName])
  }
}

// --------------
// Creates 3 CloudFront signed cookies
// They're effectively an IAM policy, a private signature to prove it's valid,
// and a reference to which key pair ID was used
// --------------

function cookiesHeaders (config) {
  const sessionDuration = parseInt(config.sessionDuration, 10)
  // create signed cookies
  const signedCookies = cloudfront.getSignedCookies('https://' + config.websiteDomain + '/*', {
    expireTime: new Date().getTime() + (sessionDuration * 1000),
    keypairId: config.cloudFrontKeypairId,
    privateKeyString: config.cloudFrontPrivateKey
  })
  // extra options for all cookies we write
  // var date = new Date()
  // date.setTime(date + (config.cookieExpiryInSeconds * 1000))
  const options = '; Domain=' + config.websiteDomain + '; Path=/; Secure; HttpOnly'
  // we use a combination of lower/upper case
  // because we need to send multiple cookies
  // but the AWS API requires all headers in a single object!
  return {
    'Set-Cookie': 'CloudFront-Policy=' + signedCookies['CloudFront-Policy'] + options,
    'SEt-Cookie': 'CloudFront-Signature=' + signedCookies['CloudFront-Signature'] + options,
    'SET-Cookie': 'CloudFront-Key-Pair-Id=' + signedCookies['CloudFront-Key-Pair-Id'] + options
  }
}
