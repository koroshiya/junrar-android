package gnu.testlet.gnu.crypto.mac;

// ----------------------------------------------------------------------------
// $Id: TestOfTMMH16.java,v 1.3 2005/10/06 04:24:20 rsdio Exp $
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

import gnu.crypto.mac.IMac;
import gnu.crypto.mac.TMMH16;
import gnu.crypto.prng.BasePRNG;
import gnu.crypto.prng.IRandom;
import gnu.crypto.prng.LimitReachedException;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Conformance test for the {@link TMMH16} implementation.</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfTMMH16 implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private IRandom keystream;
   private byte[] output, message, result;
   private IMac mac;
   private HashMap attributes = new HashMap();

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfTMMH16");

      /*
      KEY_LENGTH: 10
      TAG_LENGTH: 2
      key: { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc }
      message: { 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xde }
      output: { 0x9d, 0x6a }
      */
      try {
         attributes.clear();
         keystream = new DummyKeystream();
         keystream.init(null);

         output = new byte[] { (byte) 0x9d, (byte) 0x6a };
         mac = new TMMH16();
         attributes.put(TMMH16.KEYSTREAM, keystream);
         attributes.put(TMMH16.TAG_LENGTH, new Integer(2));
         mac.init(attributes);
         message = new byte[] {
            (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, (byte) 0xba, (byte) 0xde
         };
         for (int i = 0; i < message.length; i++) {
            mac.update(message[i]);
         }
         result = mac.digest();
         harness.check(Arrays.equals(result, output), "testVector1");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfTMMH16.testVector1");
      }

      /*
      KEY_LENGTH: 10
      TAG_LENGTH: 2
      key: { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc }
      message: { 0xca, 0xfe, 0xba }
      output: { 0xc8, 0x8e }
      */
      try {
         attributes.clear();
         keystream = new DummyKeystream();
         keystream.init(null);

         output = new byte[] { (byte) 0xc8, (byte) 0x8e };
         mac = new TMMH16();
         attributes.put(TMMH16.KEYSTREAM, keystream);
         attributes.put(TMMH16.TAG_LENGTH, new Integer(2));
         mac.init(attributes);
         message = new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba};
         for (int i = 0; i < message.length; i++) {
            mac.update(message[i]);
         }
         result = mac.digest();
         harness.check(Arrays.equals(result, output), "testVector2");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfTMMH16.testVector2");
      }

      /*
      KEY_LENGTH: 10
      TAG_LENGTH: 4
      key: { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc }
      message: { 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xde }
      output: { 0x9d, 0x6a, 0xc0, 0xd3 }
      */
      try {
         attributes.clear();
         keystream = new DummyKeystream();
         keystream.init(null);

         output = new byte[] { (byte) 0x9d, (byte) 0x6a, (byte) 0xc0, (byte) 0xd3 };
         mac = new TMMH16();
         attributes.put(TMMH16.KEYSTREAM, keystream);
         attributes.put(TMMH16.TAG_LENGTH, new Integer(4));
         mac.init(attributes);
         message = new byte[] {
            (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, (byte) 0xba, (byte) 0xde
         };
         for (int i = 0; i < message.length; i++) {
            mac.update(message[i]);
         }
         result = mac.digest();
         harness.check(Arrays.equals(result, output), "testVector3");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfTMMH16.testVector3");
      }
   }

   // Inner class(es)
   // =========================================================================

   class DummyKeystream extends BasePRNG {

      DummyKeystream() {
         super("???");
      }

      public Object clone() {
         return null;
      }

      public void setup(Map attributes) {
      }

      public void fillBlock() throws LimitReachedException {
         buffer = new byte[] {
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            (byte) 0xfe, (byte) 0xdc
         };
      }
   }
}
