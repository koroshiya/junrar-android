package gnu.testlet.gnu.crypto.sig.rsa;

// ----------------------------------------------------------------------------
// $Id: TestOfRSASignatureCodec.java,v 1.2 2005/10/06 04:24:21 rsdio Exp $
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

import gnu.crypto.key.rsa.RSAKeyPairGenerator;
import gnu.crypto.sig.BaseSignature;
import gnu.crypto.sig.ISignatureCodec;
import gnu.crypto.sig.rsa.RSAPSSSignature;
import gnu.crypto.sig.rsa.RSAPSSSignatureRawCodec;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

/**
 * <p>Conformance tests for the RSA signature format encoding/decoding
 * implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfRSASignatureCodec implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
   private KeyPair kp;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      testSignatureRawCodec(harness);
   }

   public void testSignatureRawCodec(TestHarness harness) {
      harness.checkPoint("TestOfRSASignatureCodec.testSignatureRawCodec");
      try {
         setUp();
         RSAPublicKey pubK = (RSAPublicKey) kp.getPublic();
         RSAPrivateKey secK = (RSAPrivateKey) kp.getPrivate();

         RSAPSSSignature alice = new RSAPSSSignature();
         RSAPSSSignature bob = (RSAPSSSignature) alice.clone();

         byte[] message = "1 if by land, 2 if by sea...".getBytes();

         HashMap map = new HashMap();
         map.put(BaseSignature.SIGNER_KEY, secK);
         alice.setupSign(map);
         alice.update(message, 0, message.length);
         Object signature = alice.sign();

         ISignatureCodec codec = new RSAPSSSignatureRawCodec();

         byte[] encodedSignature = codec.encodeSignature(signature);
         Object decodedSignature = codec.decodeSignature(encodedSignature);

         map.put(BaseSignature.VERIFIER_KEY, pubK);
         bob.setupVerify(map);
         bob.update(message, 0, message.length);

         harness.check(bob.verify(decodedSignature));
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRSASignatureCodec.testSignatureRawCodec");
      }
   }

   // helper methods ----------------------------------------------------------

   private void setUp() {
      HashMap map = new HashMap();
      map.put(RSAKeyPairGenerator.MODULUS_LENGTH, new Integer(1024));

      kpg.setup(map);
      kp = kpg.generate();
   }
}
