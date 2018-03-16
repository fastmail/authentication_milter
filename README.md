Authentication Milter
---------------------

A Perl implementation of email authentication standards rolled up into a single easy to use milter.

This milter verifies using the following standards.

- SPF
- SenderID
- DKIM (including ADSP)
- DMARC
- IPRev
- Check HELO matches it's IP address

Includes 3 additional modules.

- TLS (milter protocol only) - identifies TLS protected connections
- AddID - add a header to all email (example)
- ReturnOK - Checks that return addresses have properly configured MX records

Badges
------

[![Code on GitHub](https://img.shields.io/badge/github-repo-blue.svg)](https://github.com/fastmail/authentication_milter) [![Build Status](https://travis-ci.org/fastmail/authentication_milter.svg?branch=master)](https://travis-ci.org/fastmail/authentication_milter) [![Open Issues](https://img.shields.io/github/issues/fastmail/authentication_milter.svg)](https://github.com/fastmail/authentication_milter/issues) [![Dist on CPAN](https://img.shields.io/cpan/v/Mail-Milter-Authentication.svg)](https://metacpan.org/release/Mail-Milter-Authentication) [![CPANTS](https://img.shields.io/badge/cpants-kwalitee-blue.svg)](http://cpants.cpanauthors.org/dist/Mail-Milter-Authentication)

Protocol
--------

Authentication Milter is able to run as a sendmail style milter, or a SMTP style after queue filter.

A very basic subset of SMTP is implemented which allows use as an after queue filter in postfix (and others)

The XFORWARD SMTP extension is supported to allow the original connection details to be passed through to
the milter.

The milter does NOT store it's current email on disk, all processing is done in memory.
When running in SMTP mode the milter does not issue a 250 queued response until the destination MTA has also
done so.

See [Postfix After-Queue Content Filter](http://www.postfix.org/FILTER_README.html)

Note: When running in SMTP mode please do not allow untrusted clients to connect to the milter directly, always
filter these connections through your usual MTA first.

Limitations: SMTP protocol does not yet support detection of Authenticated connections.

Metrics
-------

Authentication Milter optionally collects and exposes metrics in a promethius compatible format.

The authentication milter metrics port it a http service which provides some basic information about the running
server, and also provides a standard dashboard file for grafana.

The grafana dashboard can be imported into grafana and provides rows for all installed modules which support the metrics feature.

Point your browser at the port configured in metric_connection to access this feature.

Design Decisions
----------------

- Works as either a milter or a SMTP filter.
- Do not reject mail during normal operation unless configured to do so.
  - Add headers to allow filtering as required.
- Try to handle failures gracefully.
- Handle IPv4 and IPv6 properly
- Detect Internal/Private IP addresses and skip IP checks.
- Detect authenticated connections and skip irrelevant checks (milter mode only).
  - It is assumed that this milter runs after DKIM signatures are generated, these are still validated.
- DMARC reporting should be possible.
- Modular design to allow new checks to be implemented easily.

Mailing Lists and DMARC
-----------------------

Mailing lists are a major source of DKIM, SPF, and DMARC failures. Legitimately modifying messages and resending with
differing from addresses and from IP addresses is a legitimate use of email, however this can be a cause of false positives
and result in legitimate email being quarantined or rejected.

This milter can optionally detect messages with a List-Id header, and include a flag in the resulting DMARC failure in the
Authentication-Results header.  This header can then be used to apply a more lenient filter.

DMARC failures with p=reject can optionally be rejected, and emails with a detected list id can be exempted from this rejection.
A whitelist can be setup to excempt rejections based on IP address or valid DKIM domain.

Trust Model
-----------

- For Authenticated connections we only check the DKIM signature.
- For Local IPs we only check the DKIM signature.
- For Trusted IPs we only check the DKIM signature, additionally, for Trusted IPs we do not remove any Authentication headers already present.

Installation
------------

### CPAN

To install the latest version released to CPAN, run the following commands:

 - cpanm Mail::Milter::Authentication

### From source

To install this module from source, run the following commands:

 - perl Makefile.PL
 - make
 - make test
 - make install

The DMARC module requires a little extra setup.

 - A database needs to be created and populated
 - A config file /etc/mail-dmarc.ini needs to be created

Please see the documentation for Mail::DMARC for details.

Config
------

Please see the output of 'authentication_milter --help'

Credits and License
-------------------

Copyright (c) 2018 Marc Bradshaw. <marc@marcbradshaw.net>

This is free software; you can redistribute it and/or modify it under the
same terms as the Perl 5 programming language system itself.

See [LICENSE](LICENSE) file for license details.

Who is using this?
------------------

[FastMail](https://www.fastmail.com/) are using this to perform SPF/DKIM/DMARC checks on email.

Contributing
------------

Please fork and send pull requests.

