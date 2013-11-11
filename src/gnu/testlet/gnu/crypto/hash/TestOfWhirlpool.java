package gnu.testlet.gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: TestOfWhirlpool.java,v 1.2 2005/10/06 04:24:19 rsdio Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
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

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.hash.Whirlpool;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

/**
 * <p>Conformance tests for the {@link Whirlpool} hash implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfWhirlpool implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final String TV1 =
         "EBAA1DF2E97113BE187EB0303C660F6E643E2C090EF2CDA9A2EA6DCF5002147D"+
         "1D0E1E9D996E879CEF9D26896630A5DB3308D5A0DC235B199C38923BE2259E03";
   private static final String TV2 =
         "5777FC1F8467A1C004CD9130439403CCDAA9FDC86092D9CFFE339E6008612374"+
         "D04C8FC0C724707FEAE6F7CEB1E030CABF652A673DA1849B02654AF76EEE24A7";

   private IMessageDigest algorithm, clone;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfWhirlpool");
      try {
         algorithm = new Whirlpool();
         harness.check(algorithm.selfTest(), "selfTest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfWhirlpool.selfTest");
      }

      try {
         algorithm = new Whirlpool();
         algorithm.update((byte) 0x00);
         byte[] md = algorithm.digest();
         harness.check(TV1.equals(Util.toString(md)), "test8ZeroBits");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfWhirlpool.test8ZeroBits");
      }

      try {
         algorithm = new Whirlpool();
         algorithm.update((byte) 0x00);
         algorithm.update((byte) 0x00);
         byte[] md = algorithm.digest();
         harness.check(TV2.equals(Util.toString(md)), "test16ZeroBits");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfWhirlpool.test16ZeroBits");
      }

      try {
         algorithm = new Whirlpool();
         algorithm.update((byte) 0x00);
         clone = (IMessageDigest) algorithm.clone();
         byte[] md = algorithm.digest();
         harness.check(TV1.equals(Util.toString(md)), "testCloning #1");

         clone.update((byte) 0x00);
         md = clone.digest();
         harness.check(TV2.equals(Util.toString(md)), "testCloning #2");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfWhirlpool.testCloning");
      }
   }
}
