/* AllCertificatesSamePolicyTest2_1.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;

public class AllCertificatesSamePolicyTest2_1 extends BaseValidTest
{
  public AllCertificatesSamePolicyTest2_1()
  {
    super (new String[] { "data/certs/AllCertificatesNoPoliciesTest2EE.crt",
                          "data/certs/NoPoliciesCACert.crt" },
           new String[] { "data/crls/NoPoliciesCACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
  }
}
