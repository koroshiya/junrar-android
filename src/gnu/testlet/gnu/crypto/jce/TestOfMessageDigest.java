package gnu.testlet.gnu.crypto.jce;

// --------------------------------------------------------------------------
// $Id: TestOfMessageDigest.java,v 1.4 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.jce.GnuSecurity;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Iterator;

/**
 * <p>Conformance tests for the JCE Provider implementations of MessageDigest
 * SPI classes.</p>
 *
 * @version $Revision: 1.4 $
 */
public class TestOfMessageDigest implements Testlet {

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

      testUnknownHash(harness);
      testEquality(harness);
      testCloneability(harness);
   }

   /** Should fail with an unknown algorithm. */
   public void testUnknownHash(TestHarness harness) {
      harness.checkPoint("testUnknownHash");
      try {
         MessageDigest.getInstance("Gaudot", Registry.GNU_SECURITY);
         harness.fail("testUnknownHash()");
      } catch (Exception x) {
         harness.check(true);
      }
   }

   /**
    * Tests if the result of using a hash through gnu.crypto Factory classes
    * yields same value as using instances obtained the JCE way.
    */
   public void testEquality(TestHarness harness) {
      harness.checkPoint("testEquality");
      String mdName;
      IMessageDigest gnu = null;
      MessageDigest jce = null;
      byte[] in = this.getClass().getName().getBytes();
      byte[] ba1, ba2;
      for (Iterator it = HashFactory.getNames().iterator(); it.hasNext(); ) {
         mdName = (String) it.next();
         try {
            gnu = HashFactory.getInstance(mdName);
            harness.check(gnu != null, "HashFactory.getInstance("+mdName+")");
         } catch (InternalError x) {
            harness.fail("HashFactory.getInstance("+mdName+"): "+String.valueOf(x));
         }

         try {
            jce = MessageDigest.getInstance(mdName, Registry.GNU_SECURITY);
            harness.check(jce != null, "MessageDigest.getInstance()");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("MessageDigest.getInstance("+mdName+"): "+String.valueOf(x));
         }

         gnu.update(in, 0, in.length);
         ba1 = gnu.digest();
         ba2 = jce.digest(in);

         harness.check(Arrays.equals(ba1, ba2), "testEquality("+mdName+")");
      }
   }

   /**
    * Tests if the result of a cloned, partially in-progress hash instance, when
    * used later to further process data, yields the same result as the original
    * copy.
    */
   public void testCloneability(TestHarness harness) {
      harness.checkPoint("testCloneability");
      String mdName;
      MessageDigest md1, md2;
      byte[] abc = "abc".getBytes();
      byte[] in = this.getClass().getName().getBytes();
      byte[] ba1, ba2;
      for (Iterator it = GnuSecurity.getMessageDigestNames().iterator(); it.hasNext(); ) {
         mdName = (String) it.next();
         try {
            md1 = MessageDigest.getInstance(mdName, Registry.GNU_SECURITY);

            md1.update(abc); // start with abc
            md2 = (MessageDigest) md1.clone(); // now clone it

            ba1 = md1.digest(in); // now finish both with in
            ba2 = md2.digest(in);

            harness.check(Arrays.equals(ba1, ba2), "testCloneability("+mdName+")");
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("testCloneability("+mdName+"): "+String.valueOf(x));
         }
      }
   }

   // helper methods ----------------------------------------------------------

   private void setUp() {
      Security.addProvider(new GnuSecurity()); // dynamically adds our provider
   }
}
