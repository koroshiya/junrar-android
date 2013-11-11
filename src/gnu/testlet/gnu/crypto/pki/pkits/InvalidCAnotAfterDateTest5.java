/* InvalidCAnotAfterDateTest5.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidCAnotAfterDateTest5 extends BaseInvalidTest
{
  public InvalidCAnotAfterDateTest5()
  {
    super(new String[] { "data/certs/InvalidCAnotAfterDateTest5EE.crt",
                         "data/certs/BadnotAfterDateCACert.crt" },
          new String[] { "data/crls/BadnotAfterDateCACRL.crl" });
  }
}
