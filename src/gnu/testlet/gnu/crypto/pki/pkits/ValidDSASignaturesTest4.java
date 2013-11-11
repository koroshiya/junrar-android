/* ValidDSASignaturesTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidDSASignaturesTest4 extends BaseValidTest
{
  public ValidDSASignaturesTest4()
  {
    super(new String[] { "data/certs/ValidDSASignaturesTest4EE.crt", "data/certs/DSACACert.crt" },
          new String[] { "data/crls/DSACACRL.crl" });
  }
}
