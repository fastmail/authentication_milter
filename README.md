Authentication Milter
---------------------

A PERL implemtation of email authentication standards rolled up into a single easy to use milter.

This milter verifies using the following standards.

- SPF
- SenderID
- DKIM
- DKIM-ADSP
- DMARC
- IPREV
- Check HELO matches it's IP address

Design Decisions
----------------

- Do not reject any mail, ever.
  - Add headers to allow filtering as required.
- Try and handle failures gracefully.
- Handle IPv4 and IPv6 properly
- Detect Internal/Private IP addresses and skip IP checks.
- Detect authenticated connections and skip irrelevant checks.
  - It is assumed that this milter runs after DKIM signatures are generated, these are still validated.
- DMARC reporting should be possible.

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


