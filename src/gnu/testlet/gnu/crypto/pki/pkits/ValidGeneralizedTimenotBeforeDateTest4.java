/* ValidGeneralizedTimenotBeforeDateTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidGeneralizedTimenotBeforeDateTest4 extends BaseValidTest
{
  public ValidGeneralizedTimenotBeforeDateTest4()
  {
    super(new String[] { "data/certs/ValidGeneralizedTimenotBeforeDateTest4EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
