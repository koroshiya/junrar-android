/* InvalidWrongCRLTest6.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidWrongCRLTest6 extends BaseInvalidTest
{
  public InvalidWrongCRLTest6()
  {
    super(new String[] { "data/certs/InvalidWrongCRLTest6EE.crt",
                         "data/certs/WrongCRLCACert.crt" },
          new String[] { "data/crls/WrongCRLCACRL.crl" });
  }
}
