const nock = require('nock');
const { doLookup, startup } = require('../integration');
jest.setTimeout(5000);

const options = {
  host: 'https://urlhaus-api.abuse.ch/v1',
  minUrl: 0,
  blocklist: '',
  domainBlocklistRegex: '',
  ipBlocklistRegex: '',
  maxConcurrent: 20,
  minTime: 1
};

const ip = {
  type: 'IPv4',
  value: '209.141.60.230',
  isPrivateIP: false,
  isIPv4: true
};

const url = {
  type: 'url',
  value: 'sartocarnevale.com',
  isURL: true
};

const hash = {
  type: 'hash',
  value: '45430fec6bdfc406866088097e80e10ae57e16962b535b917cd574c50408a425',
  isSHA256: true
};

const Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.error(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
});

[502, 504].forEach((statusCode) => {
  test(`${statusCode} response when calling 'https://urlhaus-api.abuse.ch/v1/host' should result in 'isGatewayTimeout'`, (done) => {
    const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/host/').reply(statusCode);
    doLookup([ip], options, (err, lookupResults) => {
      // console.info(JSON.stringify(lookupResults, null, 4));
      expect(lookupResults.length).toBe(1);
      const details = lookupResults[0].data.details;
      expect(details.maxRequestQueueLimitHit).toBe(false);
      expect(details.isConnectionReset).toBe(false);
      expect(details.isGatewayTimeout).toBe(true);
      done();
    });
  });

  test(`${statusCode} response when calling 'https://urlhaus-api.abuse.ch/v1/url' should result in 'isGatewayTimeout'`, (done) => {
    const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/url/').reply(statusCode);
    doLookup([url], options, (err, lookupResults) => {
      //console.info(JSON.stringify(lookupResults, null, 4));
      expect(lookupResults.length).toBe(1);
      const details = lookupResults[0].data.details;
      expect(details.maxRequestQueueLimitHit).toBe(false);
      expect(details.isConnectionReset).toBe(false);
      expect(details.isGatewayTimeout).toBe(true);
      done();
    });
  });

  test(`${statusCode} response when calling 'https://urlhaus-api.abuse.ch/v1/payload' should result in 'isGatewayTimeout'`, (done) => {
    const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/payload/').reply(statusCode);
    doLookup([hash], options, (err, lookupResults) => {
      console.info(JSON.stringify(lookupResults, null, 4));
      expect(lookupResults.length).toBe(1);
      const details = lookupResults[0].data.details;
      expect(details.maxRequestQueueLimitHit).toBe(false);
      expect(details.isConnectionReset).toBe(false);
      expect(details.isGatewayTimeout).toBe(true);
      done();
    });
  });
});

test('ECONNRESET response when calling `https://urlhaus-api.abuse.ch/v1/host` should result in `isConnectionReset`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/host/').replyWithError({ code: 'ECONNRESET' });
  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('ECONNRESET response when calling `https://urlhaus-api.abuse.ch/v1/url` should result in `isConnectionReset`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/url/').replyWithError({ code: 'ECONNRESET' });
  doLookup([url], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});

test('ECONNRESET response when calling `https://urlhaus-api.abuse.ch/v1/payload` should result in `isConnectionReset`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post('/payload/').replyWithError({ code: 'ECONNRESET' });
  doLookup([hash], options, (err, lookupResults) => {
    // console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(true);
    expect(details.isGatewayTimeout).toBe(false);
    done();
  });
});
