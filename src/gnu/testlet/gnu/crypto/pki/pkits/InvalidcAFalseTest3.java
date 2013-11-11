/* InvalidcAFalseTest3.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidcAFalseTest3 extends BaseInvalidTest
{
  public InvalidcAFalseTest3()
  {
    super(new String[] { "data/certs/InvalidcAFalseTest3EE.crt",
                         "data/certs/basicConstraintsNotCriticalcAFalseCACert.crt" },
          new String[] { "data/crls/basicConstraintsNotCriticalcAFalseCACRL.crl" });
  }
}
