/* InvalidBasicSelfIssuedOldWithNewTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidBasicSelfIssuedOldWithNewTest2 extends BaseInvalidTest
{
  public InvalidBasicSelfIssuedOldWithNewTest2()
  {
    super(new String[] { "data/certs/InvalidBasicSelfIssuedOldWithNewTest2EE.crt",
                         "data/certs/BasicSelfIssuedNewKeyOldWithNewCACert.crt",
                         "data/certs/BasicSelfIssuedNewKeyCACert.crt" },
          new String[] { "data/crls/BasicSelfIssuedNewKeyCACRL.crl" });
  }
}
