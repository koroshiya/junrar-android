/* InvalidBadCRLSignatureTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidBadCRLSignatureTest4 extends BaseInvalidTest
{
  public InvalidBadCRLSignatureTest4()
  {
    super(new String[] { "data/certs/InvalidBadCRLSignatureTest4EE.crt",
                         "data/certs/BadCRLSignatureCACert.crt" },
          new String[] { "data/crls/BadCRLSignatureCACRL.crl" });
  }
}
