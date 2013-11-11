/* InvalidNameChainingOrderTest2.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class InvalidNameChainingOrderTest2 extends BaseInvalidTest
{
  public InvalidNameChainingOrderTest2()
  {
    super(new String[] { "data/certs/InvalidNameChainingOrderTest2EE.crt", "data/certs/NameOrderingCACert.crt" },
          new String[] { "data/crls/NameOrderCACRL.crl" });
  }
}
