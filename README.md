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
- Detect Internal/Private IP addresses and skip IP checks
- Detect authenticated connections and skip irrelevant checks
  - It is assumed that this milter runs after DKIM signatures are generated, these are still validated.
- DMARC reporting should be possible

Trust Model
-----------

- For Authenticated connections we only check the DKIM signature.
- For Local IPs we only check the DKIM signature.
- For Trusted IPs we only check the DKIM signature, additionally, for Trusted IPs we do not remove any Authentication headers already present.

