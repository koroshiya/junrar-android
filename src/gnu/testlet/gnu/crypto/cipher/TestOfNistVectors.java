package gnu.testlet.gnu.crypto.cipher;

// ---------------------------------------------------------------------------
// $Id: TestOfNistVectors.java,v 1.5 2005/10/06 04:24:19 rsdio Exp $
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
// ---------------------------------------------------------------------------

// Tags: GNU-CRYPTO

import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>A generic cipher conformance test against NIST-style test vectors. To
 * run a test for a particular cipher, include the files `ecb_vt.txt',
 * `ecb_vk.txt', `ecb_e_m.txt', `ecb_d_m.txt', `cbc_e_m.txt', and
 * `cbc_d_m.txt' in the directory `tv/ciphername-blocksize'.</p>
 *
 * <p>That is, to test Rijndael with a 128 bit block size, put the appropriate
 * (and appropriately named) files into the directory `tv/rijndael-128'. Then
 * create an instance of this class with e.g.
 *
 * <blockquote>
 *   <code>test = new TestOfNistVectors("rijndael", 16);</code>
 * </blockquote>
 *
 * or
 *
 * <blockquote>
 *   <code>test = new TestOfNistVectors("rijndael");</code>
 * </blockquote>
 *
 * to exercise the algorithm with a 128-bit (16 bytes) block size --which is
 * the block size value for AES.</p>
 *
 * <p>Use <code>test()</code> as your test case.</p>
 *
 * <p>Note that a full-conformance test will likely take a while to finish
 * (it would have to do 48,001,152 encryptions or decryptions).</p>
 *
 * <p>References:</p>
 * <ol>
 *    <li><a href="http://csrc.nist.gov/encryption/aes/katmct/katmct.htm">Known
 *    Answer Tests and Monte Carlo Tests for AES Submissions</a> for an
 *    explanation of the tests and the format of the resulting files.</li>
 * </ol>
 *
 * @version $Revision: 1.5 $
 */
public class TestOfNistVectors implements Testlet {

   // Constants and variables
   // ------------------------------------------------------------------------

   // file names.
   protected static final String ECB_VK = "ecb_vk.txt";
   protected static final String ECB_VT = "ecb_vt.txt";
   protected static final String ECB_E_M = "ecb_e_m.txt";
   protected static final String ECB_D_M = "ecb_d_m.txt";
   protected static final String CBC_E_M = "cbc_e_m.txt";
   protected static final String CBC_D_M = "cbc_d_m.txt";

   protected static final int ENCRYPTION = 0;
   protected static final int DECRYPTION = 1;

   // Endianness.
   public static final int BIG_ENDIAN = 0;
   public static final int LITTLE_ENDIAN = 1;

   protected String algorithm;
   protected IBlockCipher cipher;
   protected HashMap attrib;
   protected URL ecb_vk;
   protected URL ecb_vt;
   protected URL ecb_e_m;
   protected URL ecb_d_m;
   protected URL cbc_e_m;
   protected URL cbc_d_m;
   protected int endianness;

   // Constructor(s)
   // ------------------------------------------------------------------------

   /**
    * <p>Constructor to instantiate a test case for the AES block cipher
    * algorithm, with 128-bit block size.</p>
    *
    * @throws InternalError if the designated algorithm is not supported.
    * @throws ExceptionInInitializerError if an error occurs during the
    * instantiation of the desired cipher algorithm.
    */
   public TestOfNistVectors() {
      this("aes", BIG_ENDIAN);
   }

   /**
    * <p>Constructor to instantiate a test case for a designated symmetric key
    * block cipher algorithm, with 128-bit block size (AES block size).</p>
    *
    * @param algorithm the name of the symmetric key block cipher to exercise.
    * @throws InternalError if the designated algorithm is not supported.
    * @throws ExceptionInInitializerError if an error occurs during the
    * instantiation of the desired cipher algorithm.
    */
   public TestOfNistVectors(String algorithm, int endianness) {
      this(algorithm, 16, endianness);
   }

   /**
    * <p>Constructor to instantiate a test case for a designated symmetric key
    * block cipher algorithm, with a given block-size (in bytes).</p>
    *
    * @param algorithm the name of the symmetric key block cipher to exercise.
    * @param blockSize the block size to use, in bytes, with the designated
    * algorithm.
    * @throws InternalError if the designated algorithm is not supported.
    * @throws ExceptionInInitializerError if an error occurs during the
    * instantiation of the desired cipher algorithm.
    */
   public TestOfNistVectors(String algorithm, int blockSize, int endianness) {
      super();

      this.endianness = endianness;
      this.algorithm = algorithm;
      cipher = CipherFactory.getInstance(algorithm);
      attrib = new HashMap();
      attrib.put(IBlockCipher.CIPHER_BLOCK_SIZE, new Integer(blockSize));
      attrib.put(IBlockCipher.KEY_MATERIAL, new byte[cipher.defaultKeySize()]);
      try {
         cipher.init(attrib);
      } catch (Exception x) {
         throw new ExceptionInInitializerError(x);
      }
   }

   // Class methods.
   // -----------------------------------------------------------------------

   // Instance methods.
   // ------------------------------------------------------------------------

   /**
    * <p>Converts a given hexadecimal string to a byte array.</p>
    *
    * @param s the string consisting of hexadecimal characters to convert into
    * a byte array.
    */
   protected byte[] stringToBytes(String s) {
      if (endianness == BIG_ENDIAN) {
         return Util.toBytesFromString(s);
      } else {
         return Util.toReversedBytesFromString(s);
      }
   }

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfNistVectors("+algorithm+")");

      String path1 = "/tv/nist/" + cipher.name().toLowerCase() + "/";
      String path2 = "/tv/nist/" + this.algorithm.trim() + "/";

      String s = "Conformance(" + cipher.name() + "): ";
      try {
         ecb_vk = this.getClass().getResource(path1 + ECB_VK);
         if (ecb_vk == null) {
            ecb_vk = this.getClass().getResource(path2 + ECB_VK);
         }

         ecb_vt = this.getClass().getResource(path1 + ECB_VT);
         if (ecb_vt == null) {
            ecb_vt = this.getClass().getResource(path2 + ECB_VT);
         }

         ecb_e_m = this.getClass().getResource(path1 + ECB_E_M);
         if (ecb_e_m == null) {
            ecb_e_m = this.getClass().getResource(path2 + ECB_E_M);
         }
         ecb_d_m = this.getClass().getResource(path1 + ECB_D_M);
         if (ecb_d_m == null) {
            ecb_d_m = this.getClass().getResource(path2 + ECB_D_M);
         }

         cbc_e_m = this.getClass().getResource(path1 + CBC_E_M);
         if (cbc_e_m == null) {
            cbc_e_m = this.getClass().getResource(path2 + CBC_E_M);
         }

         cbc_d_m = this.getClass().getResource(path1 + CBC_D_M);
         if (cbc_d_m == null) {
            cbc_d_m = this.getClass().getResource(path2 + CBC_D_M);
         }

         if (ecb_vk != null) {
            KatTest(harness, ecb_vk.openStream());
         }
         if (ecb_vt != null) {
            KatTest(harness, ecb_vt.openStream());
         }
         if (ecb_e_m != null) {
            MCTestECB(harness, ecb_e_m.openStream(), ENCRYPTION);
         }
         if (ecb_d_m != null) {
            MCTestECB(harness, ecb_d_m.openStream(), DECRYPTION);
         }
         if (cbc_e_m != null) {
            MCTestCBC(harness, cbc_e_m.openStream(), ENCRYPTION);
         }
         if (cbc_d_m != null) {
            MCTestCBC(harness, cbc_d_m.openStream(), DECRYPTION);
         }
      } catch (Exception x) {
         harness.debug(x);
         harness.fail(s + x.getMessage());
      }
   }

   // Own methods -------------------------------------------------------------

   /** Variable-key and variable-text known answer tests. */
   protected void KatTest(TestHarness harness, InputStream tvIn)
   throws Exception {
      LineNumberReader in = new LineNumberReader(new InputStreamReader(tvIn));
      String line;
      byte[] key = null;
      byte[] pt = null;
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] ect = null;
      while ((line = in.readLine()) != null) {
         if (line.startsWith("KEYSIZE=")) {
            int ks = Integer.parseInt(line.substring(line.indexOf('=')+1));
            key = new byte[ks / 8];
         } else if (line.startsWith("PT=")) {
            pt = stringToBytes(line.substring(line.indexOf('=')+1));
         } else if (line.startsWith("KEY=")) {
            key = stringToBytes(line.substring(line.indexOf('=')+1));
            attrib.put(IBlockCipher.KEY_MATERIAL, key);
         } else if (line.startsWith("CT=")) {
            ect = stringToBytes(line.substring(line.indexOf('=')+1));
            cipher.reset();
            cipher.init(attrib);
            cipher.encryptBlock(pt, 0, ct, 0);
            harness.check(Arrays.equals(ct, ect));
         }
         // Other lines are ignored.
      }
      in.close();
   }

   /** Electronic codebook mode monte carlo tests. */
   protected void MCTestECB(TestHarness harness, InputStream tvIn, int mode)
   throws Exception {
      LineNumberReader in = new LineNumberReader(new InputStreamReader(tvIn));
      String line;
      byte[] key = new byte[cipher.defaultKeySize()];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] et = new byte[cipher.currentBlockSize()];
      while ((line = in.readLine()) != null) {
         if (line.startsWith("KEYSIZE=")) {
            int ks = Integer.parseInt(line.substring(line.indexOf('=')+1));
            key = new byte[ks / 8];
         } else if (line.startsWith("PT=")) {
            if (mode == DECRYPTION) {
               et = stringToBytes(line.substring(line.indexOf('=')+1));
               cipher.reset();
               cipher.init(attrib);
               for (int i = 0; i < 10000; i++) {
                  cipher.decryptBlock(ct, 0, pt, 0);
                  System.arraycopy(pt, 0, ct, 0, pt.length);
               }
               harness.check(Arrays.equals(pt, et));
            } else {
               pt = stringToBytes(line.substring(line.indexOf('=')+1));
            }
         } else if (line.startsWith("KEY=")) {
            key = stringToBytes(line.substring(line.indexOf('=')+1));
            attrib.put(IBlockCipher.KEY_MATERIAL, key);
         } else if (line.startsWith("CT=")) {
            if (mode == ENCRYPTION) {
               et = stringToBytes(line.substring(line.indexOf('=')+1));
               cipher.reset();
               cipher.init(attrib);
               for (int i = 0; i < 10000; i++) {
                  cipher.encryptBlock(pt, 0, ct, 0);
                  System.arraycopy(ct, 0, pt, 0, ct.length);
               }
               harness.check(Arrays.equals(ct, et));
            } else {
               ct = stringToBytes(line.substring(line.indexOf('=')+1));
            }
         }
         // Other lines are ignored.
      }
      in.close();
   }

   /** Cipher block chaining mode monte carlo test. */
   protected void MCTestCBC(TestHarness harness, InputStream tvIn, int mode)
   throws Exception {
      LineNumberReader in = new LineNumberReader(new InputStreamReader(tvIn));
      String line;
      byte[] key = new byte[cipher.defaultKeySize()];
      byte[] pt = new byte[cipher.currentBlockSize()];
      byte[] ct = new byte[cipher.currentBlockSize()];
      byte[] et = new byte[cipher.currentBlockSize()];
      byte[] last = new byte[cipher.currentBlockSize()];
      byte[] iv = new byte[cipher.currentBlockSize()];
      cipher.reset();
      while ((line = in.readLine()) != null) {
         if (line.startsWith("KEYSIZE=")) {
            int ks = Integer.parseInt(line.substring(line.indexOf('=')+1));
            key = new byte[ks / 8];
            if (mode == ENCRYPTION) {
               for (int i = 0; i < ct.length; i++) {
                  ct[i] = 0;
               }
            } else {
               for (int i = 0; i < pt.length; i++) {
                  pt[i] = 0;
               }
            }
         } else if (line.startsWith("PT=")) {
            if (mode == DECRYPTION) {
               et = stringToBytes(line.substring(line.indexOf('=')+1));
               cipher.reset();
               cipher.init(attrib);
               for (int i = 0; i < 10000; i++) {
                  cipher.decryptBlock(ct, 0, pt, 0);
                  for (int j = 0; j < pt.length; j++) {
                     pt[j] ^= iv[j];
                  }
                  System.arraycopy(ct, 0, iv, 0, ct.length);
                  System.arraycopy(pt, 0, ct, 0, pt.length);
               }
               harness.check(Arrays.equals(pt, et));
            } else {
               pt = stringToBytes(line.substring(line.indexOf('=')+1));
            }
         } else if (line.startsWith("KEY=")) {
            key = stringToBytes(line.substring(line.indexOf('=')+1));
            attrib.put(IBlockCipher.KEY_MATERIAL, key);
         } else if (line.startsWith("CT=")) {
            if (mode == ENCRYPTION) {
               et = stringToBytes(line.substring(line.indexOf('=')+1));
               cipher.reset();
               cipher.init(attrib);
               for (int i = 0; i < 10000; i++) {
                  for (int j = 0; j < pt.length; j++) {
                     pt[j] ^= iv[j];
                  }
                  System.arraycopy(ct, 0, last, 0, ct.length);
                  cipher.encryptBlock(pt, 0, ct, 0);
                  System.arraycopy(ct, 0, iv, 0, ct.length);
                  System.arraycopy(last, 0, pt, 0, last.length);
               }
               harness.check(Arrays.equals(ct, et));
            } else {
               ct = stringToBytes(line.substring(line.indexOf('=')+1));
            }
         } else if (line.startsWith("IV=")) {
            iv = stringToBytes(line.substring(line.indexOf('=')+1));
         }
         // Other lines are ignored.
      }
      in.close();
   }
}
