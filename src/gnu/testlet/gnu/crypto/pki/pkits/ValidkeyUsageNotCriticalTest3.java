/* ValidkeyUsageNotCriticalTest3.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidkeyUsageNotCriticalTest3 extends BaseValidTest
{
  public ValidkeyUsageNotCriticalTest3()
  {
    super(new String[] { "data/certs/ValidkeyUsageNotCriticalTest3EE.crt",
                         "data/certs/keyUsageNotCriticalCACert.crt" },
          new String[] { "data/crls/keyUsageNotCriticalCACRL.crl" });
  }
}
