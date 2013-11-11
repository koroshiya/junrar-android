/* InvalidLongSerialNumberTest18.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidLongSerialNumberTest18 extends BaseInvalidTest
{
  public InvalidLongSerialNumberTest18()
  {
    super(new String[] { "data/certs/InvalidLongSerialNumberTest18EE.crt",
                         "data/certs/LongSerialNumberCACert.crt" },
          new String[] { "data/crls/LongSerialNumberCACRL.crl" });
  }
}
