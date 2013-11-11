/* ValidGeneralizedTimenotAfterDateTest8.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidGeneralizedTimenotAfterDateTest8 extends BaseValidTest
{
  public ValidGeneralizedTimenotAfterDateTest8()
  {
    super(new String[] { "data/certs/ValidGeneralizedTimenotAfterDateTest8EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
