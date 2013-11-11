/* InvalidCAnotBeforeDateTest1.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidCAnotBeforeDateTest1 extends BaseInvalidTest
{
  public InvalidCAnotBeforeDateTest1()
  {
    super(new String[] { "data/certs/InvalidCAnotBeforeDateTest1EE.crt",
                         "data/certs/BadnotBeforeDateCACert.crt" },
          new String[] { "data/crls/BadnotBeforeDateCACRL.crl" });
  }
}
