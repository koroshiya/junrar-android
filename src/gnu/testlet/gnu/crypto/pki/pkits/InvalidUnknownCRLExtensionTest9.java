/* InvalidUnknownCRLExtensionTest9.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidUnknownCRLExtensionTest9 extends BaseInvalidTest
{
  public InvalidUnknownCRLExtensionTest9()
  {
    super(new String[] { "data/certs/InvalidUnknownCRLExtensionTest9EE.crt",
                         "data/certs/UnknownCRLExtensionCACert.crt" },
          new String[] { "data/crls/UnknownCRLExtensionCACRL.crl" });
  }
}
