package gnu.testlet.gnu.crypto.jce;

// --------------------------------------------------------------------------
// $Id: TestOfSignature.java,v 1.3 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2001, 2002, 2004 Free Software Foundation, Inc.
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

/**
 * Conformance tests for the JCE signature scheme implementations.<p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfSignature implements Testlet {

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

      testUnknownScheme(harness);
      testDSSRawSignature(harness);
      testRSAPSSRawSignature(harness);
   }


   /** Should fail with an unknown scheme. */
   public void testUnknownScheme(TestHarness harness) {
      harness.checkPoint("testUnknownScheme");
      try {
         Signature.getInstance("ABC", Registry.GNU_SECURITY);
         harness.fail("testUnknownScheme()");
      } catch (Exception x) {
         harness.check(true);
      }
   }

   public void testDSSRawSignature(TestHarness harness) {
      harness.checkPoint("testDSSRawSignature");
      try {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", Registry.GNU_SECURITY);
         kpg.initialize(512);
         KeyPair kp = kpg.generateKeyPair();

         Signature alice = Signature.getInstance("DSA", Registry.GNU_SECURITY);
         Signature bob = (Signature) alice.clone();

         byte[] message = "1 if by land, 2 if by sea...".getBytes();

         alice.initSign(kp.getPrivate());
         alice.update(message);
         byte[] signature = alice.sign();

         bob.initVerify(kp.getPublic());
         bob.update(message);

         harness.check(bob.verify(signature), "Verify own signature");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("testDSSRawSignature(): "+String.valueOf(x));
      }
   }

   public void testRSAPSSRawSignature(TestHarness harness) {
      harness.checkPoint("testRSAPSSRawSignature");
      try {
         KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", Registry.GNU_SECURITY);
         kpg.initialize(1024);
         KeyPair kp = kpg.generateKeyPair();

         Signature alice = Signature.getInstance("RSA-PSS", Registry.GNU_SECURITY);
         Signature bob = (Signature) alice.clone();

         byte[] message = "Que du magnifique...".getBytes();

         alice.initSign(kp.getPrivate());
         alice.update(message);
         byte[] signature = alice.sign();

         bob.initVerify(kp.getPublic());
         bob.update(message);

         harness.check(bob.verify(signature), "Verify own signature");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("testRSAPSSRawSignature(): "+String.valueOf(x));
      }
   }

   // helper methods
   // -------------------------------------------------------------------------

   private void setUp() {
      Security.addProvider(new GnuSecurity()); // dynamically adds our provider
   }
}
