/* InvalidcAFalseTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidcAFalseTest2 extends BaseInvalidTest
{
  public InvalidcAFalseTest2()
  {
    super(new String[] { "data/certs/InvalidcAFalseTest2EE.crt",
                         "data/certs/basicConstraintsCriticalcAFalseCACert.crt" },
          new String[] { "data/crls/basicConstraintsCriticalcAFalseCACRL.crl" });
  }
}
