/* PKITS.java
   Copyright (C) 2003  Free Software Foundation, Inc.

   Distributed under the GPL. See the file `COPYING' */


package gnu.testlet.gnu.crypto.pki.pkits;

public class PKITS
{

  static
  {
    String clazz = System.getProperty ("pkits.provider.class",
                                       "gnu.crypto.pki.provider.GnuPki");
    String provider = System.getProperty ("pkits.provider", "GNU-PKI");
    try
      {
        if (java.security.Security.getProvider (provider) == null)
            java.security.Security.addProvider ((java.security.Provider)
                                                Class.forName (clazz).newInstance());
      }
    catch (Throwable t)
      {
        System.err.println ("WARNING: couldn't load PKITS test provider " +
                            provider + " with class " + clazz);
        System.err.println (t);
        t.printStackTrace();
      }
  }

  // Constants.
  // -------------------------------------------------------------------------

  public static final String ANY_POLICY         = "2.5.29.32.0";
  public static final String NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
  public static final String NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
  public static final String NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";
  public static final String NIST_TEST_POLICY_4 = "2.16.840.1.101.3.2.1.48.4";
  public static final String NIST_TEST_POLICY_5 = "2.16.840.1.101.3.2.1.48.5";
  public static final String NIST_TEST_POLICY_6 = "2.16.840.1.101.3.2.1.48.6";
}
