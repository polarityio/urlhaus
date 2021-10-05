'use strict';

const request = require('request');
const _ = require('lodash');
const config = require('./config/config');
const fs = require('fs');
const Bottleneck = require('bottleneck/es5');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_ENTITY_LENGTH = 100;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);
let limiter = null;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupLimiter(options) {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

const _lookupEntity = (entity, options, cb) => {
  let requestOptions = {
    method: 'POST',
    json: true
  };

  if (entity.isIPv4 || entity.isDomain) {
    requestOptions.uri = `${options.host}/host/`;
    requestOptions.form = {
      host: entity.value
    };
  } else if (entity.isURL) {
    requestOptions.uri = `${options.host}/url/`;
    requestOptions.form = {
      url: entity.value
    };
  } else if (entity.isMD5) {
    requestOptions.uri = `${options.host}/payload/`;
    requestOptions.form = {
      md5_hash: entity.value
    };
  } else if (entity.isSHA256) {
    requestOptions.uri = `${options.host}/payload/`;
    requestOptions.form = {
      sha256_hash: entity.value
    };
  } else {
    return;
  }

  requestWithDefaults(requestOptions, (err, res, body) => {
    if (err) {
      Logger.error(err, 'Request Error');
      cb({
        detail: 'Unexpected Error',
        error: err
      });
    }

    if (res && res.statusCode) {
      const errorMsg = res && res.body;

      switch (res.statusCode) {
        case 200:
          // A 200 status can be returned from the Urlhaus API with no results.
          // Checking if the status is 'ok', guarantees there is data returned for the searched entity.
          res.body.query_status === 'ok'
            ? cb(null, { entity, data: { summary: [], details: res.body } })
            : cb(null, { entity, data: null });
          break;
        case 404:
          cb(null, { entity, data: null });
          break;
        case 401:
        case 403:
          cb(null, {
            entity,
            isVolatile: true,
            data: {
              summary: [],
              details: {
                errorMessage: errorMsg,
                allowRetry: false
              }
            }
          });
          break;
        default:
          cb({
            statusCode: res.statusCode,
            detail: errorMsg ? errorMsg : `Unexpected ${res.statusCode} status code received`
          });
      }
    }
  });
};

function doLookup(entities, options, cb) {
  const lookupResults = [];
  const errors = [];
  const blockedEntities = [];
  let numConnectionResets = 0;
  let numThrottled = 0;
  let hasValidIndicator = false;

  _setupRegexBlocklists(options);

  Logger.debug(entities);

  if (!limiter) _setupLimiter(options);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      hasValidIndicator = true;
      limiter.submit(_lookupEntity, entity, options, (err, result) => {
        const maxRequestQueueLimitHit =
          (_.isEmpty(err) && _.isEmpty(result)) || (err && err.message === 'This job has been dropped by Bottleneck');

        const statusCode = _.get(err, 'statusCode', '');
        const isGatewayTimeout = statusCode === 502 || statusCode === 504;
        const isConnectionReset = _.get(err, 'error.code', '') === 'ECONNRESET';

        if (maxRequestQueueLimitHit || isConnectionReset || isGatewayTimeout) {
          // Tracking for logging purposes
          if (isConnectionReset) numConnectionResets++;
          if (maxRequestQueueLimitHit) numThrottled++;

          lookupResults.push({
            entity,
            isVolatile: true,
            data: {
              summary: ['! Lookup limit reached'],
              details: {
                maxRequestQueueLimitHit,
                isConnectionReset,
                isGatewayTimeout,
                summaryTag: '! Lookup limit reached',
                errorMessage:
                  'The search failed due to the API search limit. You can retry your search by pressing the "Retry Search" button.'
              }
            }
          });
        } else if (err) {
          errors.push(err);
        } else {
          lookupResults.push(result);
        }

        if (lookupResults.length + errors.length + blockedEntities.length === entities.length) {
          if (numConnectionResets > 0 || numThrottled > 0) {
            log.warn(
              {
                numEntitiesLookedUp: entities.length,
                numConnectionResets: numConnectionResets,
                numLookupsThrottled: numThrottled
              },
              'Lookup Limit Error'
            );
          }
          // we got all our results
          if (errors.length > 0) {
            cb(errors);
          } else {
            cb(null, lookupResults);
          }
        }
      });
    } else {
      blockedEntities.push(entity);
    }
  });

  if (!hasValidIndicator) {
    cb(null, []);
  }
}

function onMessage(payload, options, callback) {
  switch (payload.action) {
    case 'RETRY_LOOKUP':
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
  }
}

function _isInvalidEntity(entity) {
  // Domains should not be over 100 characters long so if we get any of those we don't look them up
  if (entity.value.length > MAX_ENTITY_LENGTH) {
    return true;
  }

  // Domain labels (the parts in between the periods, must be 63 characters or less
  if (entity.isDomain) {
    const invalidLabel = entity.value.split('.').find((label) => {
      return label.length > MAX_DOMAIN_LABEL_LENGTH;
    });

    if (typeof invalidLabel !== 'undefined') {
      return true;
    }
  }

  if (entity.isIPv4 && IGNORED_IPS.has(entity.value)) {
    return true;
  }

  return false;
}

function _isEntityBlocklisted(entity, options) {
  const blocklist = options.blocklist;

  Logger.trace({ blocklist: blocklist }, 'checking to see what blocklist looks like');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainBlocklistRegex !== null) {
      if (domainBlocklistRegex.test(entity.value)) {
        Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
}

function _isMiss(body) {
  if (!body) {
    return true;
  }
}

module.exports = {
  doLookup: doLookup,
  onMessage: onMessage,
  startup: startup
};
