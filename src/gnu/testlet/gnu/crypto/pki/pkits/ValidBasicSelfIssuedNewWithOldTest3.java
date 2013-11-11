/* ValidBasicSelfIssuedNewWithOldTest3.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidBasicSelfIssuedNewWithOldTest3 extends BaseValidTest
{
  public ValidBasicSelfIssuedNewWithOldTest3()
  {
    super(new String[] { "data/certs/ValidBasicSelfIssuedNewWithOldTest3EE.crt",
                         "data/certs/BasicSelfIssuedOldKeyNewWithOldCACert.crt",
                         "data/certs/BasicSelfIssuedOldKeyCACert.crt" },
          new String[] { "data/crls/BasicSelfIssuedOldKeyCACRL.crl" });
  }
}
