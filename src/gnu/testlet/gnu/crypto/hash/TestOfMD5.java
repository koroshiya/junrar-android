package gnu.testlet.gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: TestOfMD5.java,v 1.2 2005/10/06 04:24:19 rsdio Exp $
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
import gnu.crypto.hash.MD5;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

/**
 * Conformance tests for the MD5 implementation.
 *
 * @version $Revision: 1.2 $
 */
public class TestOfMD5 implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private IMessageDigest algorithm, clone;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfMD5");
      try {
         algorithm = new MD5();
         harness.check(algorithm.selfTest(), "selfTest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.selfTest");
      }

      try {
         algorithm = new MD5();
         algorithm.update("a".getBytes(), 0, 1);
         byte[] md = algorithm.digest();
         String exp = "0CC175B9C0F1B6A831C399E269772661";
         harness.check(exp.equals(Util.toString(md)), "testA");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testA");
      }

      try {
         algorithm = new MD5();
         algorithm.update("abc".getBytes(), 0, 3);
         byte[] md = algorithm.digest();
         String exp = "900150983CD24FB0D6963F7D28E17F72";
         harness.check(exp.equals(Util.toString(md)), "testABC");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testABC");
      }

      try {
         algorithm = new MD5();
         algorithm.update("message digest".getBytes(), 0, 14);
         byte[] md = algorithm.digest();
         String exp = "F96B697D7CB7938D525A2F31AAF161D0";
         harness.check(exp.equals(Util.toString(md)), "testMessageDigest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testMessageDigest");
      }

      try {
         algorithm = new MD5();
         algorithm.update("abcdefghijklmnopqrstuvwxyz".getBytes(), 0, 26);
         byte[] md = algorithm.digest();
         String exp = "C3FCD3D76192E4007DFB496CCA67E13B";
         harness.check(exp.equals(Util.toString(md)), "testAlphabet");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testAlphabet");
      }

      try {
         algorithm = new MD5();
         algorithm.update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes(), 0, 62);
         byte[] md = algorithm.digest();
         String exp = "D174AB98D277D9F5A5611C2C9F419D9F";
         harness.check(exp.equals(Util.toString(md)), "testAsciiSubset");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testAsciiSubset");
      }

      try {
         algorithm = new MD5();
         algorithm.update("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes(), 0, 80);
         byte[] md = algorithm.digest();
         String exp = "57EDF4A22BE3C955AC49DA2E2107B67A";
         harness.check(exp.equals(Util.toString(md)), "testEightyNumerics");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testEightyNumerics");
      }

      try {
         algorithm = new MD5();
         algorithm.update("a".getBytes(), 0, 1);
         clone = (IMessageDigest) algorithm.clone();
         byte[] md = algorithm.digest();
         String exp = "0CC175B9C0F1B6A831C399E269772661";
         harness.check(exp.equals(Util.toString(md)), "testCloning #1");

         clone.update("bc".getBytes(), 0, 2);
         md = clone.digest();
         exp = "900150983CD24FB0D6963F7D28E17F72";
         harness.check(exp.equals(Util.toString(md)), "testCloning #2");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfMD5.testCloning");
      }
   }
}
