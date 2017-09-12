Authentication Milter SMIME
--------------------------

SMIME handler module for [Authentication Milter](https://github.com/fastmail/authentication_milter).
A Perl implementation of email authentication standards rolled up into a single easy to use milter.

These handlers are not considered production ready and may not be fully documented.

Badges
------

[![Code on GitHub](https://img.shields.io/badge/github-repo-blue.svg)](https://github.com/fastmail/authentication_milter_smime) [![Build Status](https://travis-ci.org/fastmail/authentication_milter_smime.svg?branch=master)](https://travis-ci.org/fastmail/authentication_milter_smime) [![Open Issues](https://img.shields.io/github/issues/fastmail/authentication_milter_smime.svg)](https://github.com/fastmail/authentication_milter_smime/issues) [![Dist on CPAN](https://img.shields.io/cpan/v/Mail-Milter-Authentication-SMIME.svg)](https://metacpan.org/release/Mail-Milter-Authentication-SMIME) [![CPANTS](https://img.shields.io/badge/cpants-kwalitee-blue.svg)](http://cpants.cpanauthors.org/dist/Mail-Milter-Authentication-SMIME)

Installation
------------

You will first need to install and configure Authentication Milter

To install this module, run the following commands:

 - perl Makefile.PL
 - make
 - make test
 - make install

Config
------

Please see the output of 'authentication_milter --help SMIME

Credits and License
-------------------

Copyright (c) 2017 Marc Bradshaw. <marc@marcbradshaw.net>

This is free software; you can redistribute it and/or modify it under the
same terms as the Perl 5 programming language system itself.

See [LICENSE](LICENSE) file for license details.

Contributing
------------

Please fork and send pull requests.

