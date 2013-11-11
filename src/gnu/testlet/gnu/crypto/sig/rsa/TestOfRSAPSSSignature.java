package gnu.testlet.gnu.crypto.sig.rsa;

// ----------------------------------------------------------------------------
// $Id: TestOfRSAPSSSignature.java,v 1.4 2005/10/06 04:24:21 rsdio Exp $
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
import gnu.crypto.key.rsa.RSAKeyPairGenerator;
import gnu.crypto.sig.BaseSignature;
import gnu.crypto.sig.rsa.RSAPSSSignature;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

/**
 * <p>Conformance tests for the RSA-PSS signature generation/verification
 * implementation.</p>
 *
 * @version $Revision: 1.4 $
 */
public class TestOfRSAPSSSignature implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
   private RSAPublicKey publicK;
   private RSAPrivateKey privateK;
   private RSAPSSSignature alice, bob;
   private byte[] message;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      testSigWithDefaults(harness);
      testSigWithShaSalt16(harness);
      testSigWithRipeMD160Salt8(harness);
   }

   public void testSigWithDefaults(TestHarness harness) {
      harness.checkPoint("TestOfRSAPSSSignature.testSigWithDefaults");
      try {
         setUp();

         alice = new RSAPSSSignature(); // SHA + 0-octet salt
         bob = (RSAPSSSignature) alice.clone();

         message = "1 if by land, 2 if by sea...".getBytes();

         HashMap map = new HashMap();
         map.put(BaseSignature.SIGNER_KEY, privateK);
         alice.setupSign(map);
         alice.update(message, 0, message.length);
         Object signature = alice.sign();

         map.put(BaseSignature.VERIFIER_KEY, publicK);
         bob.setupVerify(map);
         bob.update(message, 0, message.length);

         harness.check(bob.verify(signature));
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRSAPSSSignature.testSigWithDefaults");
      }
   }

   public void testSigWithShaSalt16(TestHarness harness) {
      harness.checkPoint("TestOfRSAPSSSignature.testSigWithShaSalt16");
      try {
         setUp();

         alice = new RSAPSSSignature(Registry.SHA1_HASH, 16);
         bob = (RSAPSSSignature) alice.clone();

         message = "Que du magnifique...".getBytes();

         HashMap map = new HashMap();
         map.put(BaseSignature.SIGNER_KEY, privateK);
         alice.setupSign(map);
         alice.update(message, 0, message.length);
         Object signature = alice.sign();

         map.put(BaseSignature.VERIFIER_KEY, publicK);
         bob.setupVerify(map);
         bob.update(message, 0, message.length);

         harness.check(bob.verify(signature));
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRSAPSSSignature.testSigWithShaSalt16");
      }
   }

   public void testSigWithRipeMD160Salt8(TestHarness harness) {
      harness.checkPoint("TestOfRSAPSSSignature.testSigWithRipeMD160Salt8");
      try {
         setUp();

         alice = new RSAPSSSignature(Registry.RIPEMD160_HASH, 8);
         bob = (RSAPSSSignature) alice.clone();

         message = "abcdefghijklmnopqrstuvwxyz0123456789".getBytes();

         HashMap map = new HashMap();
         map.put(BaseSignature.SIGNER_KEY, privateK);
         alice.setupSign(map);
         alice.update(message, 0, message.length);
         Object signature = alice.sign();

         map.put(BaseSignature.VERIFIER_KEY, publicK);
         bob.setupVerify(map);
         bob.update(message, 0, message.length);

         harness.check(bob.verify(signature));
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRSAPSSSignature.testSigWithRipeMD160Salt8");
      }
   }

   // helper methods
   // -------------------------------------------------------------------------

   private void setUp() {
      kpg.setup(new HashMap()); // default is to use 1024-bit keys
      KeyPair kp = kpg.generate();
      publicK = (RSAPublicKey) kp.getPublic();
      privateK = (RSAPrivateKey) kp.getPrivate();
   }
}
