/* AllCertificatesSamePolicyTest1_2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;
import java.util.Collections;

public class AllCertificatesSamePolicyTest1_2 extends BaseValidTest
{
  public AllCertificatesSamePolicyTest1_2()
  {
    super (new String[] { "data/certs/ValidCertificatePathTest1EE.crt",
                          "data/certs/GoodCACert.crt" },
           new String[] { "data/crls/GoodCACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
    params.setExplicitPolicyRequired (true);
    params.setInitialPolicies (Collections.singleton (NIST_TEST_POLICY_1));
  }
}
