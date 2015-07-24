Authentication Milter
---------------------

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

This milter verifies using the following standards.

- SPF
- SenderID
- DKIM (including ADSP)
- DMARC
- IPRev
- Check HELO matches it's IP address

Includes 2 additional modules.

- TLS (milter protocol only) - identifies TLS protected connections
- AddID - add a header to all email (example)
- ReturnOK - Checks that return addresses have properly configured MX records

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

Design Decisions
----------------

- Works as either a milter or a SMTP filter.
- Do not reject mail during normal operation.
  - Add headers to allow filtering as required.
- Try and handle failures gracefully.
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

Trust Model
-----------

- For Authenticated connections we only check the DKIM signature.
- For Local IPs we only check the DKIM signature.
- For Trusted IPs we only check the DKIM signature, additionally, for Trusted IPs we do not remove any Authentication headers already present.

Installation
------------

To install this module, run the following commands:

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

Copyright (c) 2015 Marc Bradshaw. <marc@marcbradshaw.net>

This is free software; you can redistribute it and/or modify it under the
same terms as the Perl 5 programming language system itself.

See [LICENSE](LICENSE) file for license details.

Who is using this?
------------------

[FastMail](https://www.fastmail.com/) are using this to perform SPF/DKIM/DMARC checks on email.

Contributing
------------

Please fork and send pull requests.

