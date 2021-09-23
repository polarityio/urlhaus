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

test('502 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).reply(502);
  doLookup([ip], options, (err, lookupResults) => {
    console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('504 response should result in `isGatewayTimeout`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).reply(504);
  doLookup([ip], options, (err, lookupResults) => {
    //console.info(JSON.stringify(lookupResults, null, 4));
    expect(lookupResults.length).toBe(1);
    const details = lookupResults[0].data.details;
    expect(details.maxRequestQueueLimitHit).toBe(false);
    expect(details.isConnectionReset).toBe(false);
    expect(details.isGatewayTimeout).toBe(true);
    done();
  });
});

test('ECONNRESET response should result in `isConnectionReset`', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).replyWithError({ code: 'ECONNRESET' });
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

test('500 response should return a normal integration error', (done) => {
  const scope = nock(`https://urlhaus-api.abuse.ch/v1`).post(/.*/).reply(500);
  doLookup([ip], options, (err, lookupResults) => {
    // console.info(JSON.stringify(err, null, 4));
    expect(err.length).toBe(1);
    expect(err[0].statusCode).toBe(500);
    done();
  });
});
