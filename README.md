# Polarity URLhaus Integration

The Polarity URLhaus integration takes indicators on your screen and overlays if there are any malicious URLs associated with that indicator.

To learn more information about URLhaus, please go to: https://urlhaus.abuse.ch

Check out the integration in action below:

![urlhaus](https://user-images.githubusercontent.com/22529325/59939162-0e87ea80-9425-11e9-84c1-b120e9ae7fa0.gif)

### URLhaus URL
The base URL to use for the URLhaus API

### Domain and IP Blacklist

This is an alternate option that can be used to specify domains or IPs that you do not want sent to RiskIQ.  The data must specify the entire IP or domain to be blocked (e.g., www.google.com is treated differently than google.com).

### Domain Blacklist Regex

This option allows you to specify a regex to blacklist domains.  Any domain matching the regex will not be looked up.  If the regex is left blank then no domains will be blacklisted.

### IP Blacklist Regex

This option allows you to specify a regex to blacklist IPv4 Addresses.  Any IPv4 matching the regex will not be looked up.  If the regex is left blank then no IPv4s will be blacklisted.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
