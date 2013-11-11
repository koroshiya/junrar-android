/* ValidpathLenConstraintTest8.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidpathLenConstraintTest8 extends BaseValidTest
{
  public ValidpathLenConstraintTest8()
  {
    super(new String[] { "data/certs/ValidpathLenConstraintTest8EE.crt",
                         "data/certs/pathLenConstraint0CACert.crt" },
          new String[] { "data/crls/pathLenConstraint0CACRL.crl" });
  }
}
