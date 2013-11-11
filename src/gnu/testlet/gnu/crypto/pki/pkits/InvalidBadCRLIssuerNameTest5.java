/* InvalidBadCRLIssuerNameTest5.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidBadCRLIssuerNameTest5 extends BaseInvalidTest
{
  public InvalidBadCRLIssuerNameTest5()
  {
    super(new String[] { "data/certs/InvalidBadCRLIssuerNameTest5EE.crt",
                         "data/certs/BadCRLIssuerNameCACert.crt" },
          new String[] { "data/crls/BadCRLIssuerNameCACRL.crl" });
  }
}
