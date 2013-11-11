/* InvalidBasicSelfIssuedCRLSigningKeyTest7.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidBasicSelfIssuedCRLSigningKeyTest7 extends BaseInvalidTest
{
  public InvalidBasicSelfIssuedCRLSigningKeyTest7()
  {
    super(new String[] { "data/certs/InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt",
                         "data/certs/BasicSelfIssuedCRLSigningKeyCACert.crt" },
          new String[] { "data/crls/BasicSelfIssuedCRLSigningKeyCACRL.crl" },
          new String[] { "data/certs/BasicSelfIssuedCRLSigningKeyCRLCert.crt" });
  }
}
