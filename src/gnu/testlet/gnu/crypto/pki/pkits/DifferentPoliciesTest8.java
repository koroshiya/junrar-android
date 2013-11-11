/* DifferentPoliciesTest8.java
   Copyright (C) 2004  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;
import java.util.Collections;

public class DifferentPoliciesTest8 extends BaseInvalidTest
{
  public DifferentPoliciesTest8()
  {
    super (new String[] { "data/certs/DifferentPoliciesTest7EE.crt",
                          "data/certs/PoliciesP12subsubCAP1P2Cert.crt",
                          "data/certs/PoliciesP12subCAP1Cert.crt",
                          "data/certs/PoliciesP12CACert.crt" },
           new String[] { "data/crls/PoliciesP12subsubCAP1P2CRL.crl",
                          "data/crls/PoliciesP12subCAP1CRL.crl",
                          "data/crls/PoliciesP12CACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
    params.setInitialPolicies (Collections.EMPTY_SET);
    params.setAnyPolicyInhibited (true);
  }
}
