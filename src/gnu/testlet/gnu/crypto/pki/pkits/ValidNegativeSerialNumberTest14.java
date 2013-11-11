/* ValidNegativeSerialNumberTest14.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidNegativeSerialNumberTest14 extends BaseValidTest
{
  public ValidNegativeSerialNumberTest14()
  {
    super(new String[] { "data/certs/ValidNegativeSerialNumberTest14EE.crt",
                         "data/certs/NegativeSerialNumberCACert.crt" },
          new String[] { "data/crls/NegativeSerialNumberCACRL.crl" });
  }
}
