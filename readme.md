## WebCert - a Web Tool for Generation and Management of digital Certificates

* * *

Digital Certificates are needed everywhere in today's world. They are used
to enable secure SSL web traffic, e-mail encryption and other technologies.

To get a digital certificate, you'll either have to get one from a
commercial provider (who usually charges $$$), or you have to install,
configure and run your own certificate authority (also $$ and, at the
very least something more to learn and manage, which is very time
and resource consuming). Often we don't need the extensive functionality
and complexity of a full CA management system.

As a result, I wrote WebCert to be able to quickly generate certificates
on my own, and to enable my colleagues without knowledge of the details
to do so as well. The first version became an instant hit with over 300
certificate generations per year. It encouraged me to improve it to the
version you see here.

WebCert is using the OpenSSL libraries for certificate operations. It is
not just a frontend to the openssl program, but independently written.
It only requires standard C libraries,  the OpenSSL libraries and the CGIC
library from Thomas Boutell. As a result, you don't need to maintain any of
the web-application enabling technologies like JSP, PHP, Phyton...
It is using simple CGI technology for easiest installation and maintenance.

### External Dependencies:

*	Thomas Boutell's CGIC library, see http://www.boutell.com/cgic/

*	OpenSSL libary and headers, see http://www.openssl.org/

        make sure you have:
	-I<path-to-cgic-includes> and -L<path-to-cgic-lib> and
	-I<path-to-openssl-includes> and -L<path-to-openssl-lib>
	 in the Makefiles

### Configuration:

Apart from the Makefiles in the root and src/ dirextories, check the file
webcert.h in the src/ directory. The upper section can be configured to set
the URL location and the default webcert parameters.

### Making and installing WebCert:

*	vi Makefile and src/Makefile to adjust various path's for cgi and html
	destinations and ssl include and library directories

*	vi src/webcert.h to adjust the path's for your webserver and cert
	store (if you have one - for listing of local certificate copies)

*	vi src/certsign.h if you want to adjust certificate properties
	such as lifetime, extensions, comments, etc

*	make && make install
	"make install" expects a directory structure somewhere below your
        document root i.e. apache/htdocs/webcert containing the following sub
	directories: images cgi-bin style. The application is expected
	to be accessed via URL http://<www.yourdomain.com>/webcert.

*	don't forget to enable the cgi directory in your webserver, i.e.
	in apache's httpd.conf add the line:
 	ScriptAlias /webcert/cgi-bin/ "/var/apache/htdocs/webcert/cgi-bin/"

A more complete installation procedure is provided in INSTALL.

#### Security:

It is highly adviseable to provide access control and SSL encryption
to the WebCert interface for any use other then experimental.
The webserver writeable certificate and export directory should be secured
(i.e. by a Apache <Directory> directive).

#### Copyright and License:

WebCert was written by Frank4DD. It is distributed under the GPL.
Anybody may reproduce it, use it, send it, print it, transfer on a T-shirt,
etc. without modifying its content or removing the copyright.

#### Legal Disclaimer:

Of course this software and its created certificates come WITHOUT ANY WARRANTY.

#### Thanks and Credits:

*	to Thomas Boutell for providing the CGIC library:
*	to the authors of O'Reilly's book "Network Security with OpenSSL"
	who provided a guiding "light" in the OpenSSL jungle.
*	to the authors of OpenSSL, whose code ensures that only the
	true & dedicated will learn its power ;-)


CGIC, copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002 by Thomas Boutell
and Boutell.Com, Inc.. Permission is granted to use CGIC in any
application, commercial or noncommercial, at no cost. HOWEVER,
this copyright paragraph must appear on a "credits" page accessible
in the public online and offline documentation of the program.
Modified versions of the CGIC library should not be distributed without
the attachment of a clear statement regarding the author of the
modifications, and this notice may in no case be removed.
Modifications may also be submitted to the author for inclusion
in the main CGIC distribution.
