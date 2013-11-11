/* InvalidEEnotBeforeDateTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidEEnotBeforeDateTest2 extends BaseInvalidTest
{
  public InvalidEEnotBeforeDateTest2()
  {
    super(new String[] { "data/certs/InvalidEEnotBeforeDateTest2EE.crt",
                         "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
