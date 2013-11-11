package gnu.testlet.gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: TestOfTripleDES.java,v 1.5 2005/10/06 04:24:19 rsdio Exp $
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
//
// --------------------------------------------------------------------------

// Tags: GNU-CRYPTO
// Uses: BaseCipherTestCase

import gnu.crypto.Properties;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.cipher.TripleDES;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Conformance test for the Triple-DES cipher.</p>
 *
 * @version $Revision: 1.5 $
 */
public class TestOfTripleDES extends BaseCipherTestCase {

   // Constants and variables.
   // -----------------------------------------------------------------------

   /*
    * Test vectors from the "Triple DES Monte Carlo (Modes) Test Sample
    * Results", from <a
    * href="http://csrc.nist.gov/cryptval/des/tripledes-vectors.zip">http://csrc.nist.gov/cryptval/des/tripledes-vectors.zip</a>.
    */

   /**
    * The ECB encryption monte-carlo tests.
    */
   static final String[][] E_TV = {
      // key bytes
      // plain bytes         cipher bytes
      { "0123456789abcdef0123456789abcdef0123456789abcdef",
        "4e6f772069732074", "6a2a19f41eca854b" },
      { "0123456789abcdef23456789abcdef010123456789abcdef",
        "4e6f772069732074", "03e69f5bfa58eb42" },
      { "0123456789abcdef23456789abcdef01456789abcdef0123",
        "4e6f772069732074", "dd17e8b8b437d232" },
      { "6b085d92976149a46b085d92976149a46b085d92976149a4",
        "6a2a19f41eca854b", "ce5d6c7b63177c18" },
      { "02c4da3d73f226ad1cbce0f2bacd3b1502c4da3d73f226ad",
        "03e69f5bfa58eb42", "262a60f9743e1fd8" },
      { "dc34addf3d9d1fdc976d456702cef4fdad49c2ba0b2f975b",
        "dd17e8b8b437d232", "3145bcfc1c19382f" }
   };

   /**
    * The ECB decryption monte-carlo tests.
    */
   static final String[][] D_TV = {
      { "0123456789abcdef0123456789abcdef0123456789abcdef",
        "4e6f772069732074", "cdd64f2f9427c15d" },
      { "0123456789abcdef23456789abcdef010123456789abcdef",
        "4e6f772069732074", "6996c8fa47a2abeb" },
      { "0123456789abcdef23456789abcdef01456789abcdef0123",
        "4e6f772069732074", "8325397644091a0a" },
      { "cdf40b491c8c0db3cdf40b491c8c0db3cdf40b491c8c0db3",
        "cdd64f2f9427c15d", "5bb675e3db3a7f3b" },
      { "68b58c9dce086704529dce3719e9e0da68b58c9dce086704",
        "6996c8fa47a2abeb", "6b177e016e6ae12d" },
      { "83077c10cda2d6e5296240fd8c834fcd8fdac4fbe5ae978f",
        "8325397644091a0a", "c67901abdc008c89" }
   };

   // Constructors.
   // -----------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods.
   // -----------------------------------------------------------------------

   // Instance methods.
   // -----------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfTripleDES");
      cipher = new TripleDES();
      HashMap attrib = new HashMap();
      attrib.put(IBlockCipher.CIPHER_BLOCK_SIZE, new Integer(8));
      attrib.put(IBlockCipher.KEY_MATERIAL, new byte[24]);

      boolean oldCheckForWeakKeys = Properties.checkForWeakKeys();
      try {
         Properties.setCheckForWeakKeys(false);

         harness.check(validityTest(), "validityTest()");
         harness.check(cloneabilityTest(), "cloneabilityTest()");
         harness.check(vectorsTest(), "vectorsTest()");
         
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfTripleDES");
      } finally { // return it to its previous value
         Properties.setCheckForWeakKeys(oldCheckForWeakKeys);
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
      byte[] kb, pt, ct1, ct2 = new byte[8];
      for (int i = 0; i < E_TV.length; i++) {
         kb = Util.toBytesFromString(E_TV[i][0]);
         pt = Util.toBytesFromString(E_TV[i][1]);
         ct1 = Util.toBytesFromString(E_TV[i][2]);
         attrib.put(IBlockCipher.KEY_MATERIAL, kb);
         cipher.reset();
         cipher.init(attrib);
         cipher.encryptBlock(pt, 0, ct2, 0);
         for (int j = 0; j < 9999; j++) {
            cipher.encryptBlock(ct2, 0, ct2, 0);
         }
         if (!Arrays.equals(ct1, ct2)) {
            return false;
         }
      }

      for (int i = 0; i < D_TV.length; i++) {
         kb = Util.toBytesFromString(D_TV[i][0]);
         pt = Util.toBytesFromString(D_TV[i][1]);
         ct1 = Util.toBytesFromString(D_TV[i][2]);
         attrib.put(IBlockCipher.KEY_MATERIAL, kb);
         cipher.reset();
         cipher.init(attrib);
         cipher.decryptBlock(pt, 0, ct2, 0);
         for (int j = 0; j < 9999; j++) {
            cipher.decryptBlock(ct2, 0, ct2, 0);
         }
         if (!Arrays.equals(ct1, ct2)) {
            return false;
         }
      }
      return true;
   }
}
