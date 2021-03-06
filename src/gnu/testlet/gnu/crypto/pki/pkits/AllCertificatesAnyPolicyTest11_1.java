/* AllCertificatesAnyPolicyTest11_1.java
   Copyright (C) 2004  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;

public class AllCertificatesAnyPolicyTest11_1 extends BaseValidTest
{
  public AllCertificatesAnyPolicyTest11_1()
  {
    super (new String[] { "data/certs/AllCertificatesanyPolicyTest11EE.crt",
                          "data/certs/anyPolicyCACert.crt" },
           new String[] { "data/crls/anyPolicyCACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
  }
}
