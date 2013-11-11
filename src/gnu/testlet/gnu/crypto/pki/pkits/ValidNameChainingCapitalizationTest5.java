/* ValidNameChainingCapitalizationTest5.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidNameChainingCapitalizationTest5 extends BaseValidTest
{
  public ValidNameChainingCapitalizationTest5()
  {
    super(new String[] { "data/certs/ValidNameChainingCapitalizationTest5EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
