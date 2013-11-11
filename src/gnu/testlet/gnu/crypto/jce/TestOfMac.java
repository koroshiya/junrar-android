package gnu.testlet.gnu.crypto.jce;

// --------------------------------------------------------------------------
// $Id: TestOfMac.java,v 1.5 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2002, 2003 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License or (at your
// option) any later version.
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
// --------------------------------------------------------------------------

// Tags: GNU-CRYPTO

import gnu.crypto.Registry;
import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.mac.IMac;
import gnu.crypto.mac.MacFactory;
import gnu.crypto.mac.TMMH16;
import gnu.crypto.mac.UMac32;
import gnu.crypto.prng.IRandom;
import gnu.crypto.prng.PRNGFactory;
import gnu.crypto.jce.GnuCrypto;
import gnu.crypto.jce.spec.TMMHParameterSpec;
import gnu.crypto.jce.spec.UMac32ParameterSpec;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>Conformance tests for the JCE Provider implementations of MAC SPI classes.</p>
 *
 * @version $Revision: 1.5 $
 */
public class TestOfMac implements Testlet {

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

      testUnknownMac(harness);
      testEquality(harness);
      testCloneability(harness);
   }

   /** Should fail with an unknown algorithm. */
   public void testUnknownMac(TestHarness harness) {
      harness.checkPoint("testUnknownMac");
      try {
         Mac.getInstance("Godot", Registry.GNU_CRYPTO);
         harness.fail("testUnknownMac()");
      } catch (Exception x) {
         harness.check(true);
      }
   }

   /**
    * Tests if the result of using a MAC through gnu.crypto Factory classes
    * yields same value as using instances obtained the JCE way.
    */
   public void testEquality(TestHarness harness) {
      harness.checkPoint("testEquality");
      String macName;
      IMac gnu = null;
      Mac jce = null;
      byte[] in = this.getClass().getName().getBytes();
      byte[] ba1, ba2;
      HashMap attrib = new HashMap();
      for (Iterator it = MacFactory.getNames().iterator(); it.hasNext(); ) {
         macName = (String) it.next();
         AlgorithmParameterSpec params = null;
         if (macName.equalsIgnoreCase("UMAC32")) {
            byte[] nonce = new byte[16];
            for (int i = 0; i < nonce.length; i++) {
               nonce[i] = (byte) i;
            }
            params = new UMac32ParameterSpec(nonce);
            attrib.put(UMac32.NONCE_MATERIAL, nonce);
         } else if (macName.equalsIgnoreCase("TMMH16")) {
            IRandom rand = PRNGFactory.getInstance(Registry.MD_PRNG);
            rand.init(new HashMap());
            Integer tagLen = new Integer(4);
            params = new TMMHParameterSpec(rand, tagLen);
            try
              {
                attrib.put(TMMH16.KEYSTREAM, rand.clone());
              }
            catch (CloneNotSupportedException cnse)
              {
                throw new RuntimeException ("can't clone " + rand.getClass ());
              }
            attrib.put(TMMH16.TAG_LENGTH, tagLen);
         }

         try {
            gnu = MacFactory.getInstance(macName);
            harness.check(gnu != null, "MacFactory.getInstance("+macName+")");
         } catch (InternalError x) {
            harness.fail("MacFactory.getInstance("+macName+"): "+String.valueOf(x));
         }

         try {
            jce = Mac.getInstance(macName, Registry.GNU_CRYPTO);
            harness.check(jce != null, "Mac.getInstance()");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("Mac.getInstance("+macName+"): "+String.valueOf(x));
         }

         byte[] kb = null;
         if (macName.equalsIgnoreCase("UMAC32") || macName.equalsIgnoreCase("UHASH32")) {
            kb = new byte[16];
         } else if (macName.toLowerCase().startsWith(Registry.OMAC_PREFIX)) {
            IBlockCipher cipher = CipherFactory.getInstance(macName.substring(Registry.OMAC_PREFIX.length()));
            if (cipher != null)
               kb = new byte[cipher.defaultKeySize()];
            else
               kb = new byte[gnu.macSize()];
         } else {
            kb = new byte[gnu.macSize()];
         }
         for (int i = 0; i < kb.length; i++) {
            kb[i] = (byte) i;
         }
         attrib.put(IMac.MAC_KEY_MATERIAL, kb);
         try {
            gnu.init(attrib);
            if (macName.equalsIgnoreCase("TMMH16")) {
               jce.init(null, params);
            } else {
               jce.init(new SecretKeySpec(kb, macName), params);
            }
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("Mac.getInstance("+macName+"): "+String.valueOf(x));
         }

         gnu.update(in, 0, in.length);
         ba1 = gnu.digest();
         ba2 = jce.doFinal(in);

         harness.check(Arrays.equals(ba1, ba2), "testEquality("+macName+")");
      }
   }

   /**
    * Tests if the result of a cloned, partially in-progress hash instance,
    * when used later to further process data, yields the same result as the
    * original copy.
    */
   public void testCloneability(TestHarness harness) {
      harness.checkPoint("testCloneability");
      String macName;
      Mac mac1, mac2;
      byte[] abc = "abc".getBytes();
      byte[] in = this.getClass().getName().getBytes();
      byte[] ba1, ba2;
      for (Iterator it = MacFactory.getNames().iterator(); it.hasNext(); ) {
         macName = (String) it.next();
         try {
            AlgorithmParameterSpec params = null;
            if (macName.equalsIgnoreCase("UMAC32")) {
               byte[] nonce = new byte[16];
               for (int i = 0; i < nonce.length; i++) {
                  nonce[i] = (byte) i;
               }
               params = new UMac32ParameterSpec(nonce);
            } else if (macName.equalsIgnoreCase("TMMH16")) {
               IRandom rand = PRNGFactory.getInstance(Registry.MD_PRNG);
               rand.init(new HashMap());
               Integer tagLen = new Integer(4);
               params = new TMMHParameterSpec(rand, tagLen);
            }

            mac1 = Mac.getInstance(macName, Registry.GNU_CRYPTO);
            byte[] kb = null;
            if (macName.equalsIgnoreCase("UMAC32") || macName.equalsIgnoreCase("UHASH32")) {
               kb = new byte[16];
            } else {
               kb = new byte[mac1.getMacLength()];
            }
            for (int i = 0; i < kb.length; i++) {
               kb[i] = (byte) i;
            }

            if (macName.equalsIgnoreCase("TMMH16")) {
               mac1.init(null, params);
            } else {
               mac1.init(new SecretKeySpec(kb, macName), params);
            }

            mac1.update(abc); // start with abc
            mac2 = (Mac) mac1.clone(); // now clone it

            ba1 = mac1.doFinal(in); // now finish both with in
            ba2 = mac2.doFinal(in);

            harness.check(Arrays.equals(ba1, ba2), "testCloneability("+macName+")");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("testCloneability("+macName+"): "+String.valueOf(x));
         }
      }
   }

   // helper methods ----------------------------------------------------------

   private void setUp() {
      Security.addProvider(new GnuCrypto()); // dynamically adds our provider
   }
}
