/* ValidLongSerialNumberTest16.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidLongSerialNumberTest16 extends BaseValidTest
{
  public ValidLongSerialNumberTest16()
  {
    super(new String[] { "data/certs/ValidLongSerialNumberTest16EE.crt",
                         "data/certs/LongSerialNumberCACert.crt" },
          new String[] { "data/crls/LongSerialNumberCACRL.crl" });
  }
}
