/* ValidbasicConstraintsNotCriticalTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidbasicConstraintsNotCriticalTest4 extends BaseValidTest
{
  public ValidbasicConstraintsNotCriticalTest4()
  {
    super(new String[] { "data/certs/ValidbasicConstraintsNotCriticalTest4EE.crt",
                         "data/certs/basicConstraintsNotCriticalCACert.crt" },
          new String[] { "data/crls/basicConstraintsNotCriticalCACRL.crl" });
  }
}
