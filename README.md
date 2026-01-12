This is source code for *chkhibpwnd*, an application to query the *Have I Been Pwned API* if a password has been leaked. Its main target is OS/400. It has been tested to compile and work on OS/400 V4R5. Error reporting is not extensively tested, yet.

*Chkhibpwnd* can be found on [GitHub](https://github.com/PoC-dev/chkhibpwnd).

For details, see [API Documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords), especially regarding the extensive measures to ensure the checked password can't be derived.

### License
It is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with it; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA or get it at http://www.gnu.org/licenses/gpl.html

### Additional information
#### Crypto considerations
Because not every OS comes with a readymade library for crypto functions, I asked GitHub Copilot to come up with an implementation for generating SHA-1 hashes. The code outputs the same hashes as the *shasum* command from the Perl distribution, so I assume it's working correctly.

The remote API requires access via https, but the target platforms usually have no crypto support worth mentioning, if any. Hence I rely on an external http proxy service. External to the target machine, that is. In my case, I'm running the Apache http with a standard forward (!) proxy configuration with SSL support. To my surprise, Apache httpd happily accepts https URLs being sent to its configured proxy port via http (plain text) connections, which solves the issue at hand.

This also means that currently, you **must** provide a proxy server and you also **must** configure the `http_proxy` environment variable to point to said proxy server in URL format, e. g.
```
http://192.168.0.1:3128
```

> **Note:** There is currently no support for proxy servers requiring authentication.

Volunteers implementing IBM i support for QC3CALHA (Calculate Hashes), and TLS e. g. through GSKit for newer OS releases are invited to submit pull requests.

#### Compilation and using
Some infrastructure must be provided.
- Create the source PF:
```
     crtsrcpf qgpl/chkhibpwnd
```
- Upload the needed files to the source PF:
```
     ftp myas400 < ftpupload.txt
```
- A REXX script has been provided to create the OS/400 objects. Run it:
```
     strrexprc srcfile(qgpl/chkhibpwnd) srcmbr(compile)
```
- Now you can run it as any other command:
```
     chkhibpwnd 'test'
```
> **Note:** The quotes make sure the string is passed as is, instead of being converted to upper case.

Depending on feedback from the API, one of two possible answers are printed in the message line:
- Password has been pwned.
- Password not found in database.

### Known bugs
At the moment, using the `*cmd` object to run the application generates a wrong checksum. Meanwhile, run `call chkhibpwnd 'testthispassword'` to work around that issue.

----
2026-01-12 poc@pocnet.net
