/* InvalidBasicSelfIssuedCRLSigningKeyTest8.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidBasicSelfIssuedCRLSigningKeyTest8 extends BaseInvalidTest
{
  public InvalidBasicSelfIssuedCRLSigningKeyTest8()
  {
    super(new String[] { "data/certs/InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt",
                         "data/certs/BasicSelfIssuedCRLSigningKeyCACert.crt" },
          new String[] { "data/crls/BasicSelfIssuedCRLSigningKeyCACRL.crl" },
          new String[] { "data/certs/BasicSelfIssuedCRLSigningKeyCRLCert.crt" });
  }
}
