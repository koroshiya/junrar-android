package gnu.testlet.gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// Id: $
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
// Uses: BaseCipherTestCase

import gnu.crypto.cipher.Cast5;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Conformance test for the <code>CAST5</code> cipher. Test vectors are as
 * per RFC-2144.</p>
 *
 * @version Revision: $
 */
public class TestOfCast5 extends BaseCipherTestCase {

   // Constants and variables
   // -------------------------------------------------------------------------

   /**
    * 128-bit key   = 01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A
    *   plaintext   = 01 23 45 67 89 AB CD EF
    *   ciphertext  = 23 8B 4F E5 84 7E 44 B2
    * 80-bit  key   = 01 23 45 67 12 34 56 78 23 45
    *               = 01 23 45 67 12 34 56 78 23 45 00 00 00 00 00 00
    *   plaintext   = 01 23 45 67 89 AB CD EF
    *   ciphertext  = EB 6A 71 1A 2C 02 27 1B
    */
   private static final String[][] TV = {
      // key                                plaintext           ciphertext
      {"0123456712345678234567893456789A", "0123456789ABCDEF", "238B4FE5847E44B2"},
      {"01234567123456782345",             "0123456789ABCDEF", "EB6A711A2C02271B"}
   };

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfCast5");
      cipher = new Cast5();
      HashMap attrib = new HashMap();
      attrib.put(IBlockCipher.CIPHER_BLOCK_SIZE, new Integer(8));
      attrib.put(IBlockCipher.KEY_MATERIAL, new byte[16]);
      try {
         harness.check(validityTest(), "validityTest()");
         harness.check(cloneabilityTest(), "cloneabilityTest()");
         harness.check(vectorsTest(), "vectorsTest()");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfCast5");
      }
   }

   /** Test cloneability. */
   protected boolean cloneabilityTest() throws Exception {
      int blockSize = cipher.defaultBlockSize();
      int keySize = cipher.defaultKeySize();

      byte[] pt = new byte[blockSize];
      byte[] ct1 = new byte[blockSize];
      byte[] ct2 = new byte[blockSize];
      byte[] kb = new byte[keySize];
      HashMap attributes = new HashMap();
      attributes.put(IBlockCipher.KEY_MATERIAL, kb);

      cipher.reset();
      cipher.init(attributes);

      cipher.encryptBlock(pt, 0, pt, 0);
      IBlockCipher thomas = (IBlockCipher) cipher.clone();
      thomas.init(attributes);
      cipher.encryptBlock(pt, 0, ct1, 0);
      thomas.encryptBlock(pt, 0, ct2, 0);

      return Arrays.equals(ct1, ct2);
   }

   protected boolean vectorsTest() throws Exception {
      HashMap attrib = new HashMap();
      byte[] kb, pt, ct1, ct2 = new byte[8], cpt = new byte[8];
      for (int i = 0; i < TV.length; i++) {
         kb = Util.toBytesFromString(TV[i][0]);
         pt = Util.toBytesFromString(TV[i][1]);
         ct1 = Util.toBytesFromString(TV[i][2]);
         attrib.put(IBlockCipher.KEY_MATERIAL, kb);
         cipher.reset();
         cipher.init(attrib);
         cipher.encryptBlock(pt, 0, ct2, 0);
         if (!Arrays.equals(ct1, ct2)) {
            return false;
         }
         cipher.decryptBlock(ct2, 0, cpt, 0);
         if (!Arrays.equals(pt, cpt)) {
            return false;
         }
      }
      return true;
   }
}
