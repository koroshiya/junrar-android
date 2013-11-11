/* ValidNameChainingWhitespaceTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidNameChainingWhitespaceTest4 extends BaseValidTest
{
  public ValidNameChainingWhitespaceTest4()
  {
    super(new String[] { "data/certs/ValidNameChainingWhitespaceTest4EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
