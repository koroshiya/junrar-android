/* ValidSignaturesTest1.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidSignaturesTest1 extends BaseValidTest
{

  public ValidSignaturesTest1()
  {
    super(new String[] { "data/certs/ValidCertificatePathTest1EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
