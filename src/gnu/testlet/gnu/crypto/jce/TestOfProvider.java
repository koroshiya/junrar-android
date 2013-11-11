package gnu.testlet.gnu.crypto.jce;

// --------------------------------------------------------------------------
// $Id: TestOfProvider.java,v 1.3 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    51 Franklin Street, Fifth Floor,
//    Boston, MA 02110-1301
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
// ----------------------------------------------------------------------------

// Tags: GNU-CRYPTO

import gnu.crypto.Registry;
import gnu.crypto.jce.GnuSecurity;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import java.util.Random;

/**
 * <p>Conformance tests for the JCE Provider implementation.</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfProvider implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      setUp();

      testProviderName(harness);
      testSha(harness);
      testWhirlpool(harness);
      testShaPRNG(harness);
      testWhirlpoolPRNG(harness);
      testGNUSecureRandoms(harness);
   }

   public void testProviderName(TestHarness harness) {
      harness.checkPoint("testProviderName");
      Provider us = Security.getProvider(Registry.GNU_CRYPTO);
      harness.check(Registry.GNU_CRYPTO.equals(us.getName()));
      us = Security.getProvider(Registry.GNU_SASL);
      harness.check(Registry.GNU_SASL.equals(us.getName()));
      us = Security.getProvider(Registry.GNU_SECURITY);
      harness.check(Registry.GNU_SECURITY.equals(us.getName()));
   }

   public void testSha(TestHarness harness) {
      harness.checkPoint("testSha");
      try {
         MessageDigest md = MessageDigest.getInstance("SHA", Registry.GNU_SECURITY);
         harness.check(md != null);
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("testSha()");
      }
   }

   public void testWhirlpool(TestHarness harness) {
      harness.checkPoint("testWhirlpool");
      try {
         MessageDigest md = MessageDigest.getInstance("Whirlpool", Registry.GNU_SECURITY);
         harness.check(md != null);
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("testWhirlpool()");
      }
   }

   public void testShaPRNG(TestHarness harness) {
      harness.checkPoint("testShaPRNG");
      try {
         SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG", Registry.GNU_SECURITY);
         harness.check(rnd != null);
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("testShaPRNG()");
      }
   }

   public void testWhirlpoolPRNG(TestHarness harness) {
      harness.checkPoint("testWhirlpoolPRNG");
      try {
         SecureRandom rnd = SecureRandom.getInstance("WHIRLPOOLPRNG", Registry.GNU_SECURITY);
         harness.check(rnd != null);
      } catch (Exception x) {
         x.printStackTrace(System.err);
         harness.fail("testWhirlpoolPRNG()");
      }
   }

   public void testGNUSecureRandoms(TestHarness harness) {
      harness.checkPoint("testGNUSecureRandoms");
      String rand;
      Random algorithm;
      for (Iterator it = GnuSecurity.getSecureRandomNames().iterator(); it.hasNext(); ) {
         rand = (String) it.next();
         try {
            algorithm = null;
            algorithm = SecureRandom.getInstance(rand, Registry.GNU_SECURITY);
            harness.check(algorithm != null, "getInstance("+String.valueOf(rand)+")");
         } catch (NoSuchProviderException x) {
            harness.fail("getInstance("+String.valueOf(rand)+"): "+String.valueOf(x));
         } catch (NoSuchAlgorithmException x) {
            harness.fail("getInstance("+String.valueOf(rand)+"): "+String.valueOf(x));
         }
      }
   }

   // helper methods
   // -------------------------------------------------------------------------

   private void setUp() {
      Security.addProvider(new GnuSecurity()); // dynamically adds our provider
   }
}
