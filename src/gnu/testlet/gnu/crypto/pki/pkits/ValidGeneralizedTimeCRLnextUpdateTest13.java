/* ValidGeneralizedTimeCRLnextUpdateTest13.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidGeneralizedTimeCRLnextUpdateTest13 extends BaseValidTest
{
  public ValidGeneralizedTimeCRLnextUpdateTest13()
  {
    super(new String[] { "data/certs/ValidGeneralizedTimeCRLnextUpdateTest13EE.crt",
                         "data/certs/GeneralizedTimeCRLnextUpdateCACert.crt" },
          new String[] { "data/crls/GeneralizedTimeCRLnextUpdateCACRL.crl" });
  }
}
