package gnu.testlet.gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: BaseCipherTestCase.java,v 1.5 2005/10/06 04:24:19 rsdio Exp $
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

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.util.Util;
import gnu.testlet.Testlet;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>A generic cipher test case that can verify a cipher implementation given
 * a set of known answers. See {@link gnu.testlet.gnu.crypto.cipher.TestOfAnubis}
 * for how To implement a test of a particular cipher.</p>
 *
 * <p>The tests, as implemented in this class, are the NIST Known-Answer Tests
 * (KAT) and Monte-Carlo Tests (MCT), which were the test formats used in the
 * AES Quest. As such, these tests are suited for AES-candidates (or similar)
 * ciphers; the specific AES style parts of these tests are the 128, 192, and
 * 256 bit key lengths.</p>
 *
 * <p>References:</p>
 * <ol>
 *    <li><a href="http://csrc.nist.gov/encryption/aes/katmct/katmct.htm">Known
 *    Answer Tests and Monte Carlo Tests for AES Submissions</a> for an
 *    explanation of the tests and the format of the resulting files.</li>
 * </ol>.
 *
 * @version $Revision: 1.5 $
 */
public abstract class BaseCipherTestCase implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   /** Big-endian. */
   protected static final int BIG_ENDIAN = 0;

   /** Little-endian. */
   protected static final int LITTLE_ENDIAN = 1;

   /** The reference to the cipher implementation to exercise. */
   protected IBlockCipher cipher;

   /** The byte order to use. */
   protected int endianness;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /**
    * Default 0-arguments constructor, using the default endianness.
    */
   public BaseCipherTestCase() {
      this(BIG_ENDIAN);
   }

   /**
    * Construct a new test case, with a specified endianness.
    *
    * @param endianness The endianness that the underlying cipher
    *        expects its input to be.
    */
   public BaseCipherTestCase(int endianness) {
      this.endianness = endianness;
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Shift, in situ, the variable key/text byte array one position to the
    * right.</p>
    *
    * @param kb The bytes to shift.
    */
   private static void shiftRight1(byte[] kb) {
      int i;
      for (i = 0; kb[i] == 0 && i < kb.length; i++) { // do nothing
      }
      kb[i] = (byte)((kb[i] & 0xff) >>> 1);
      // handle byte boundary case
      if (kb[i] == 0) {
         i++;
         if (i < kb.length) {
            kb[i] = (byte) 0x80;
         }
      }
   }

   /**
    * <p>Shift, in situ, the variable key/text byte array one position to the
    * right, taking the byte order to be little-endian.</p>
    *
    * @param kb The bytes to shift.
    */
   private static void revShiftRight1(byte[] kb) {
      int i;
      for (i = kb.length-1; kb[i] == 0 && i >= 0; i--) { // do nothing
      }
      kb[i] = (byte)((kb[i] & 0xff) >>> 1);
      // handle byte boundary case
      if (kb[i] == 0) {
         i--;
         if (i >= 0) {
            kb[i] = (byte) 0x80;
         }
      }
   }

   // Instance methods
   // -------------------------------------------------------------------------

   /**
    * <p>Perform a variable-key KAT, comparing the results with the supplied
    * answers.</p>
    *
    * @param answers The expected ciphertexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> If all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   katVK(String[] answers, IBlockCipher cipher, int ks) throws Exception {
      HashMap attrib = new HashMap();
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] kb = new byte[ks];
      if (endianness == BIG_ENDIAN) {
         kb[0] = (byte) 0x80;
      } else {
         kb[ks-1] = (byte) 0x80;
      }
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      for (int i = 0; i < answers.length; i++) {
         cipher.reset();
         cipher.init(attrib);
         cipher.encryptBlock(pt, 0, ct, 0);
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(ct))) {
               return false;
            }
            shiftRight1(kb);
         } else {
            if (!answers[i].equals(Util.toReversedString(ct))) {
               return false;
            }
            revShiftRight1(kb);
         }
      }
      return true;
   }

   /**
    * <p>Perform a variable-text known-answer test, comparing the results with
    * the supplied answers.</p>
    *
    * @param answers The expected ciphertexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> If all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   katVT(String[] answers, IBlockCipher cipher, int ks) throws Exception {
      HashMap attrib = new HashMap();
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] kb = new byte[ks];
      if (endianness == BIG_ENDIAN) {
         pt[0] = (byte) 0x80;
      } else {
         pt[pt.length-1] = (byte) 0x80;
      }
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      cipher.reset();
      cipher.init(attrib);
      for (int i = 0; i < answers.length; i++) {
         cipher.encryptBlock(pt, 0, ct, 0);
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(ct))) {
               return false;
            }
            shiftRight1(pt);
         } else {
            if (!answers[i].equals(Util.toReversedString(ct))) {
               return false;
            }
            revShiftRight1(pt);
         }
      }
      return true;
   }

   /**
    * <p>Perform a Monte-Carlo encryption Test, using the ECB mode. The
    * <code>answers</code> array should be the resulting ciphertexts after each
    * iteration.</p>
    *
    * @param answers The expected ciphertexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> if all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   mctEncryptECB(String[] answers, IBlockCipher cipher, int ks)
   throws Exception {
      HashMap attrib = new HashMap();
      byte[] kb = new byte[ks];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] lct = new byte[cipher.currentBlockSize()];
      int i, j;
      int off = ks - cipher.currentBlockSize();
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      for (i = 0; i < answers.length; i++) {
         cipher.reset();
         cipher.init(attrib);
         for (j = 0; j < 10000; j++) {
            if (j == 9999) {
               System.arraycopy(ct, 0, lct, 0, ct.length);
            }
            cipher.encryptBlock(pt, 0, ct, 0);
            System.arraycopy(ct, 0, pt, 0, ct.length);
         }
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(ct))) {
               return false;
            }
         } else {
            if (!answers[i].equals(Util.toReversedString(ct))) {
               return false;
            }
         }
         for (j = 0; j + (lct.length-off) < lct.length && j < off; j++) {
            kb[j] ^= lct[j+(lct.length-off)];
         }
         for (j = 0; j + off < kb.length && j < ct.length; j++) {
            kb[j+off] ^= ct[j];
         }
      }
      return true;
   }

   /**
    * <p>Perform a Monte-Carlo decryption Test, using the ECB mode. The
    * <code>answers</code> array should be the resulting plaintexts after each
    * iteration.</p>
    *
    * @param answers The expected plaintexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> if all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   mctDecryptECB(String[] answers, IBlockCipher cipher, int ks)
   throws Exception {
      HashMap attrib = new HashMap();
      byte[] kb = new byte[ks];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] lpt = new byte[cipher.currentBlockSize()];
      int i, j;
      int off = ks - cipher.currentBlockSize();
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      for (i = 0; i < answers.length; i++) {
         cipher.reset();
         cipher.init(attrib);
         for (j = 0; j < 10000; j++) {
            if (j == 9999) {
               System.arraycopy(pt, 0, lpt, 0, ct.length);
            }
            cipher.decryptBlock(ct, 0, pt, 0);
            System.arraycopy(pt, 0, ct, 0, ct.length);
         }
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(pt))) {
               return false;
            }
         } else {
            if (!answers[i].equals(Util.toReversedString(pt))) {
               return false;
            }
         }
         for (j = 0; j + (lpt.length-off) < lpt.length && j < off; j++) {
            kb[j] ^= lpt[j+(lpt.length-off)];
         }
         for (j = 0; j + off < kb.length && j < pt.length; j++) {
            kb[j+off] ^= pt[j];
         }
      }
      return true;
   }

   /**
    * <p>Perform a Monte-Carlo encryption Test, using the CBC mode. The
    * <code>answers</code> array should be the resulting ciphertexts after each
    * iteration.</p>
    *
    * @param answers The expected ciphertexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> if all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   mctEncryptCBC(String[] answers, IBlockCipher cipher, int ks)
   throws Exception {
      HashMap attrib = new HashMap();
      byte[] kb = new byte[ks];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] lct = new byte[cipher.currentBlockSize()];
      byte[] iv = new byte[cipher.currentBlockSize()];
      int i, j, k;
      int off = ks - cipher.currentBlockSize();
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      for (i = 0; i < answers.length; i++) {
         cipher.reset();
         cipher.init(attrib);
         for (j = 0; j < 10000; j++) {
            for (k = 0; k < pt.length; k++) {
               pt[k] ^= iv[k];
            }
            System.arraycopy(ct, 0, lct, 0, ct.length);
            cipher.encryptBlock(pt, 0, ct, 0);
            System.arraycopy(ct, 0, iv, 0, ct.length);
            System.arraycopy(lct, 0, pt, 0, lct.length);
         }
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(ct))) {
               return false;
            }
         } else {
            if (!answers[i].equals(Util.toReversedString(ct))) {
               return false;
            }
         }
         for (j = 0; j + (lct.length-off) < lct.length && j < off; j++) {
            kb[j] ^= lct[j+(lct.length-off)];
         }
         for (j = 0; j + off < kb.length && j < ct.length; j++) {
            kb[j+off] ^= ct[j];
         }
      }
      return true;
   }

   /**
    * <p>Perform a Monte-Carlo decryption Test, using the CBC mode. The
    * <code>answers</code> array should be the resulting plaintexts after each
    * iteration.</p>
    *
    * @param answers The expected plaintexts.
    * @param cipher The cipher.
    * @param ks The length of the key, in bytes.
    * @return <code>true</code> if all tests succeed, <code>false</code>
    * otherwise.
    */
   protected boolean
   mctDecryptCBC(String[] answers, IBlockCipher cipher, int ks)
   throws Exception {
      HashMap attrib = new HashMap();
      byte[] kb = new byte[ks];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] lpt = new byte[cipher.currentBlockSize()];
      byte[] iv = new byte[cipher.currentBlockSize()];
      int i, j, k;
      int off = ks - cipher.currentBlockSize();
      attrib.put(IBlockCipher.KEY_MATERIAL, kb);

      for (i = 0; i < answers.length; i++) {
         cipher.reset();
         cipher.init(attrib);
         for (j = 0; j < 10000; j++) {
            if (j == 9999) {
               System.arraycopy(pt, 0, lpt, 0, pt.length);
            }
            cipher.decryptBlock(ct, 0, pt, 0);
            for (k = 0; k < pt.length; k++) {
               pt[k] ^= iv[k];
            }
            System.arraycopy(ct, 0, iv, 0, ct.length);
            System.arraycopy(pt, 0, ct, 0, pt.length);
         }
         if (endianness == BIG_ENDIAN) {
            if (!answers[i].equals(Util.toString(pt))) {
               return false;
            }
         } else {
            if (!answers[i].equals(Util.toReversedString(pt))) {
               return false;
            }
         }
         for (j = 0; j + (lpt.length-off) < lpt.length && j < off; j++) {
            kb[j] ^= lpt[j+(lpt.length-off)];
         }
         for (j = 0; j + off < kb.length && j < pt.length; j++) {
            kb[j+off] ^= pt[j];
         }
      }
      return true;
   }

   /** Test symmetry. */
   protected boolean validityTest() {
      return cipher.selfTest();
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
}
