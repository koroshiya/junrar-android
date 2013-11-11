/* InvalidpreUTC2000EEnotAfterDateTest7.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class Invalidpre2000UTCEEnotAfterDateTest7 extends BaseInvalidTest
{
  public Invalidpre2000UTCEEnotAfterDateTest7()
  {
    super(new String[] { "data/certs/Invalidpre2000UTCEEnotAfterDateTest7EE.crt", "data/certs/GoodCACert.crt" },
          new String[] { "data/crls/GoodCACRL.crl" });
  }
}
