/* InvalidRevokedCATest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidRevokedCATest2 extends BaseInvalidTest
{
  public InvalidRevokedCATest2()
  {
    super(new String[] { "data/certs/InvalidRevokedCATest2EE.crt",
                         "data/certs/RevokedsubCACert.crt",
                         "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/RevokedsubCACRL.crl",
                         "data/crls/GoodCACRL.crl" });
  }
}
