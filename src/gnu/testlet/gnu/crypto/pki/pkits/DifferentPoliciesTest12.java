/* DifferentPoliciesTest12.java
   Copyright (C) 2004  Free Software Foundation, Inc.

   Distributed under the GPL; see the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

import java.security.cert.PKIXParameters;

public class DifferentPoliciesTest12 extends BaseInvalidTest
{
  public DifferentPoliciesTest12()
  {
    super (new String[] { "data/certs/DifferentPoliciesTest12EE.crt",
                          "data/certs/PoliciesP3CACert.crt" },
           new String[] { "data/crls/PoliciesP3CACRL.crl" });
  }

  protected void setupAdditionalParams (PKIXParameters params)
  {
  }
}
