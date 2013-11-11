package gnu.testlet.gnu.crypto.mac;

// ----------------------------------------------------------------------------
// $Id: TestOfHMacSha1.java,v 1.3 2005/10/06 04:24:20 rsdio Exp $
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

import gnu.crypto.mac.IMac;
import gnu.crypto.mac.MacFactory;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Conformance tests of the HMAC-SHA1 message authentication code algorithms.</p>
 *
 * <p>References:</p>
 * <ol>
 *    <li>P. Cheng and R. Glenn, <a href="http://www.ietf.org/rfc/rfc2202.txt">RFC
 *    2202: Test Cases for HMAC-MD5 and HMAC-SHA-1</a>.</li>
 * </ol>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfHMacSha1 implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final byte[][][] TEST_VECTOR = {
      { "Jefe".getBytes(),
        "what do ya want for nothing?".getBytes(),
        Util.toBytesFromString("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79") },
      { Util.toBytesFromString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        "Hi There".getBytes(),
        Util.toBytesFromString("b617318655057264e28bc0b6fb378c8ef146be00") },
      { Util.toBytesFromString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        new byte[50] /* filled in below, 0xDD 50 times */,
        Util.toBytesFromString("125d7342b9ac11cd91a39af48aa17b4f63f175d3") },
      { Util.toBytesFromString("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        new byte[50] /* filled in below, 0xDD 50 times */,
        Util.toBytesFromString("4c9007f4026250c6bc8414f9bf50c86c2d7235da") },
      { Util.toBytesFromString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
        "Test With Truncation".getBytes(),
        Util.toBytesFromString("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04") },
      { new byte[80] /* filled in below, 0xAA 80 times */,
        "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(),
        Util.toBytesFromString("aa4ae5e15272d00e95705637ce8a3b55ed402112") },
      { new byte[80] /* filled in below, 0xAA 80 times */,
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes(),
        Util.toBytesFromString("e8e99d0f45237d786d6bbaa7965c7808bbff1a91") }
   };

   static {
      int i = 0;
      for ( ; i < 50; i++) {
         TEST_VECTOR[2][1][i] = (byte) 0xDD;
         TEST_VECTOR[3][1][i] = (byte) 0xCD;

         TEST_VECTOR[5][0][i] = (byte) 0xAA;
         TEST_VECTOR[6][0][i] = (byte) 0xAA;
      }
      for ( ; i < 80; i++) {
         TEST_VECTOR[5][0][i] = (byte) 0xAA;
         TEST_VECTOR[6][0][i] = (byte) 0xAA;
      }
   }

   private HashMap attr = new HashMap();
   private IMac mac;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfHMacSha1");
      mac = MacFactory.getInstance("hmac-sha1");
      // 1st vector SHOULD fail with key too short exception
      try {
         attr.put(IMac.MAC_KEY_MATERIAL, TEST_VECTOR[0][0]);
         mac.init(attr);
         mac.update(TEST_VECTOR[0][1], 0, TEST_VECTOR[0][1].length);
         harness.check(Arrays.equals(mac.digest(), TEST_VECTOR[0][2]), "#0");
         harness.fail("#0 - SHOULD have caused a Key too short exception but didn't");
      } catch (InvalidKeyException x) {
         harness.check(true, "#0");
      }

      for (int i = 1; i < TEST_VECTOR.length; i++) {
         try {
            attr.put(IMac.MAC_KEY_MATERIAL, TEST_VECTOR[i][0]);
            mac.init(attr);
            mac.update(TEST_VECTOR[i][1], 0, TEST_VECTOR[i][1].length);
            harness.check(Arrays.equals(mac.digest(), TEST_VECTOR[i][2]), "#"+i);
         } catch (Exception x) {
            harness.debug(x);
            harness.fail("#"+i+" - " + String.valueOf(x));
         }
      }
   }
}
