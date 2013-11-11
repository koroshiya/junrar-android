/* ValidUTF8StringEncodedNamesTest9.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */

// Tags: PKITS

package gnu.testlet.gnu.crypto.pki.pkits;

public class ValidUTF8StringEncodedNamesTest9 extends BaseValidTest
{
  public ValidUTF8StringEncodedNamesTest9()
  {
    super(new String[] { "data/certs/ValidUTF8StringEncodedNamesTest9EE.crt",
                         "data/certs/UTF8StringEncodedNamesCACert.crt" },
          new String[] { "data/crls/UTF8StringEncodedNamesCACRL.crl" });
  }
}
