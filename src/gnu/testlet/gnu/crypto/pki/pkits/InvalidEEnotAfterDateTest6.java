/* InvalidEEnotAfterDateTest6.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidEEnotAfterDateTest6 extends BaseInvalidTest
{
  public InvalidEEnotAfterDateTest6()
  {
    super(new String[] { "data/certs/InvalidEEnotAfterDateTest6EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
