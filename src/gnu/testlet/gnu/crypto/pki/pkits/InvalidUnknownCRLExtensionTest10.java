/* InvalidUnknownCRLExtensionTest10.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidUnknownCRLExtensionTest10 extends BaseInvalidTest
{
  public InvalidUnknownCRLExtensionTest10()
  {
    super(new String[] { "data/certs/InvalidUnknownCRLExtensionTest10EE.crt",
                         "data/certs/UnknownCRLExtensionCACert.crt" },
          new String[] { "data/crls/UnknownCRLExtensionCACRL.crl" });
  }
}
