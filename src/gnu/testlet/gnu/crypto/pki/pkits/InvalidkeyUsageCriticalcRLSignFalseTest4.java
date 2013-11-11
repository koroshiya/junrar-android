/* InvalidkeyUsageCriticalcRLSignFalseTest4.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidkeyUsageCriticalcRLSignFalseTest4 extends BaseInvalidTest
{
  public InvalidkeyUsageCriticalcRLSignFalseTest4()
  {
    super(new String[] { "data/certs/InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt",
                         "data/certs/keyUsageCriticalcRLSignFalseCACert.crt" },
          new String[] { "data/crls/keyUsageCriticalcRLSignFalseCACRL.crl" });
  }
}
