/* Invalidpre2000CRLnextUpdateTest12.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class Invalidpre2000CRLnextUpdateTest12 extends BaseInvalidTest
{
  public Invalidpre2000CRLnextUpdateTest12()
  {
    super(new String[] { "data/certs/Invalidpre2000CRLnextUpdateTest12EE.crt",
                         "data/certs/pre2000CRLnextUpdateCACert.crt" },
          new String[] { "data/crls/pre2000CRLnextUpdateCACRL.crl" });
  }
}
