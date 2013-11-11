/* ValidBasicSelfIssuedOldWithNewTest1.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidBasicSelfIssuedOldWithNewTest1 extends BaseValidTest
{
  public ValidBasicSelfIssuedOldWithNewTest1()
  {
    super(new String[] { "data/certs/ValidBasicSelfIssuedOldWithNewTest1EE.crt",
                         "data/certs/BasicSelfIssuedNewKeyOldWithNewCACert.crt",
                         "data/certs/BasicSelfIssuedNewKeyCACert.crt" },
          new String[] { "data/crls/BasicSelfIssuedNewKeyCACRL.crl" });
  }
}
