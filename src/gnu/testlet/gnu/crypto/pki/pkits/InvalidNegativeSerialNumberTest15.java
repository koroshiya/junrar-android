/* InvalidNegativeSerialNumberTest15.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidNegativeSerialNumberTest15 extends BaseInvalidTest
{
  public InvalidNegativeSerialNumberTest15()
  {
    super(new String[] { "data/certs/InvalidNegativeSerialNumberTest15EE.crt",
                         "data/certs/NegativeSerialNumberCACert.crt" },
          new String[] { "data/crls/NegativeSerialNumberCACRL.crl" });
  }
}
