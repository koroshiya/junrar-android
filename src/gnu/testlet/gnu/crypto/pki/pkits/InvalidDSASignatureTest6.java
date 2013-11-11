/* InvalidDSASignatureTest6.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidDSASignatureTest6 extends BaseInvalidTest
{
  public InvalidDSASignatureTest6()
  {
    super(new String[] { "data/certs/InvalidDSASignatureTest6EE.crt", "data/certs/DSACACert.crt" },
          new String[] { "data/crls/DSACACRL.crl" });
  }
}
