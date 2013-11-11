package gnu.testlet.gnu.crypto.key.dh;

// ----------------------------------------------------------------------------
// $Id: TestOfDHCodec.java,v 1.2 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2003 Free Software Foundation, Inc.
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

import gnu.crypto.key.dh.DHKeyPairRawCodec;
import gnu.crypto.key.dh.GnuDHKeyPairGenerator;
import gnu.crypto.key.dh.GnuDHPrivateKey;
import gnu.crypto.key.dh.GnuDHPublicKey;
import gnu.crypto.key.IKeyPairCodec;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * <p>Conformance tests for the Diffie-Hellman key format encoding/decoding
 * implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfDHCodec implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private GnuDHKeyPairGenerator kpg = new GnuDHKeyPairGenerator();
   private KeyPair kp;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      testKeyPairRawCodec(harness);
      testPublicKeyValueOf(harness);
      testPrivateKeyValueOf(harness);
   }

   public void testKeyPairRawCodec(TestHarness harness) {
      harness.checkPoint("TestOfDHCodec.testKeyPairRawCodec");
      setUp();

      GnuDHPublicKey pubK = (GnuDHPublicKey) kp.getPublic();
      GnuDHPrivateKey secK = (GnuDHPrivateKey) kp.getPrivate();

      byte[] pk1, pk2;
      try { // an invalid format ID
         pk1 = ((GnuDHPublicKey) pubK).getEncoded(0);
         harness.fail("Succeeded with unknown format ID");
      } catch (IllegalArgumentException x) {
         harness.check(true, "Recognised unknown format ID");
      }

      pk1 = ((GnuDHPublicKey) pubK).getEncoded(IKeyPairCodec.RAW_FORMAT);
      pk2 = ((GnuDHPrivateKey) secK).getEncoded(IKeyPairCodec.RAW_FORMAT);

      IKeyPairCodec codec = new DHKeyPairRawCodec();
      PublicKey newPubK = codec.decodePublicKey(pk1);
      PrivateKey newSecK = codec.decodePrivateKey(pk2);

      harness.check(pubK.equals(newPubK), "DH public key Raw encoder/decoder test");
      harness.check(secK.equals(newSecK), "DH private key Raw encoder/decoder test");
   }

   public void testPublicKeyValueOf(TestHarness harness) {
      harness.checkPoint("TestOfDHCodec.testPublicKeyValueOf");
      setUp();

      GnuDHPublicKey pubK = (GnuDHPublicKey) kp.getPublic();

      byte[] pk = ((GnuDHPublicKey) pubK).getEncoded(IKeyPairCodec.RAW_FORMAT);
      PublicKey newPubK = GnuDHPublicKey.valueOf(pk);

      harness.check(pubK.equals(newPubK), "DH public key valueOf(<raw-value>) test");
   }

   public void testPrivateKeyValueOf(TestHarness harness) {
      harness.checkPoint("TestOfDHCodec.testPrivateKeyValueOf");
      setUp();

      GnuDHPrivateKey privateK = (GnuDHPrivateKey) kp.getPrivate();

      byte[] pk = ((GnuDHPrivateKey) privateK).getEncoded(IKeyPairCodec.RAW_FORMAT);
      PrivateKey newSecK = GnuDHPrivateKey.valueOf(pk);

      harness.check(privateK.equals(newSecK), "DH public key valueOf(<raw-value>) test");
   }

   // helper methods ----------------------------------------------------------

   private void setUp() {
      HashMap map = new HashMap();
      map.put(GnuDHKeyPairGenerator.PRIME_SIZE, new Integer(512));
      map.put(GnuDHKeyPairGenerator.EXPONENT_SIZE, new Integer(160));

      kpg.setup(map);
      kp = kpg.generate();
   }
}
