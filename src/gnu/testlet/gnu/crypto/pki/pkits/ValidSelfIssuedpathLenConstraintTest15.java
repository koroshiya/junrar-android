/* ValidSelfIssuedpathLenConstraintTest15.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidSelfIssuedpathLenConstraintTest15 extends BaseValidTest
{
  public ValidSelfIssuedpathLenConstraintTest15()
  {
    super(new String[] { "data/certs/ValidSelfIssuedpathLenConstraintTest15EE.crt",
                         "data/certs/pathLenConstraint0SelfIssuedCACert.crt",
                         "data/certs/pathLenConstraint0CACert.crt" },
          new String[] { "data/crls/pathLenConstraint0CACRL.crl" });
  }
}
