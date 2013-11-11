/* InvalidUnknownCRLEntryExtensionTest8.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidUnknownCRLEntryExtensionTest8 extends BaseInvalidTest
{
  public InvalidUnknownCRLEntryExtensionTest8()
  {
    super(new String[] { "data/certs/InvalidUnknownCRLEntryExtensionTest8EE.crt",
                         "data/certs/UnknownCRLEntryExtensionCACert.crt" },
          new String[] { "data/crls/UnknownCRLEntryExtensionCACRL.crl" });
  }
}
