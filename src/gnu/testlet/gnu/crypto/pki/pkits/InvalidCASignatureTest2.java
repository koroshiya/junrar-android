/* InvalidCASignatureTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidCASignatureTest2 extends BaseInvalidTest
{
  public InvalidCASignatureTest2()
  {
    super(new String[] { "data/certs/InvalidCASignatureTest2EE.crt", "data/certs/BadSignedCACert.crt" },
          new String[] { "data/crls/BadSignedCACRL.crl" });
  }
}
