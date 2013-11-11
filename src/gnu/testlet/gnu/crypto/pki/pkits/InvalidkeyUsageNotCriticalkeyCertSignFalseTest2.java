/* InvalidkeyUsageNotCriticalkeyCertSignFalseTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidkeyUsageNotCriticalkeyCertSignFalseTest2 extends BaseInvalidTest
{
  public InvalidkeyUsageNotCriticalkeyCertSignFalseTest2()
  {
    super(new String[] { "data/certs/InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt",
                         "data/certs/keyUsageNotCriticalkeyCertSignFalseCACert.crt" },
          new String[] { "data/crls/keyUsageNotCriticalkeyCertSignFalseCACRL.crl" });
  }
}
