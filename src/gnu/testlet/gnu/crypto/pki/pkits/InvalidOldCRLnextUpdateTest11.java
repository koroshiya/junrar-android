/* InvalidOldCRLnextUpdateTest11.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidOldCRLnextUpdateTest11 extends BaseInvalidTest
{
  public InvalidOldCRLnextUpdateTest11()
  {
    super(new String[] { "data/certs/InvalidOldCRLnextUpdateTest11EE.crt",
                         "data/certs/OldCRLnextUpdateCACert.crt" },
          new String[] { "data/crls/OldCRLnextUpdateCACRL.crl" });
  }
}
