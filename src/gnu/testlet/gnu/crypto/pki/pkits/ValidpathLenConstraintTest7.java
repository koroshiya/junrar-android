/* ValidpathLenConstraintTest7.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidpathLenConstraintTest7 extends BaseValidTest
{
  public ValidpathLenConstraintTest7()
  {
    super(new String[] { "data/certs/ValidpathLenConstraintTest7EE.crt",
                         "data/certs/pathLenConstraint0CACert.crt" },
          new String[] { "data/crls/pathLenConstraint0CACRL.crl" });
  }
}
