/* AllCertificatesSamePoliciesTest10_1.java
   Copyright (C) 2004  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;

public class AllCertificatesSamePoliciesTest10_1 extends BaseValidTest
{
  public AllCertificatesSamePoliciesTest10_1()
  {
    super (new String[] { "data/certs/AllCertificatesSamePoliciesTest10EE.crt",
                          "data/certs/PoliciesP12CACert.crt" },
           new String[] { "data/crls/PoliciesP12CACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
  }
}
