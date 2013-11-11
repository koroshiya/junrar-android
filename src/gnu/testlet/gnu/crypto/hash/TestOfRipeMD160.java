package gnu.testlet.gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: TestOfRipeMD160.java,v 1.2 2005/10/06 04:24:19 rsdio Exp $
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
import gnu.crypto.hash.RipeMD160;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

/**
 * Conformance tests for the RipeMD160 implementation.
 *
 * @version $Revision: 1.2 $
 */
public class TestOfRipeMD160 implements Testlet {

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
      harness.checkPoint("TestOfRipeMD160");
      try {
         algorithm = new RipeMD160();
         harness.check(algorithm.selfTest(), "selfTest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.selfTest");
      }

      try {
         algorithm = new RipeMD160();
         algorithm.update("a".getBytes(), 0, 1);
         byte[] md = algorithm.digest();
         String exp = "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE";
         harness.check(exp.equals(Util.toString(md)), "testA");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.testA");
      }

      try {
         algorithm = new RipeMD160();
         algorithm.update("abc".getBytes(), 0, 3);
         byte[] md = algorithm.digest();
         String exp = "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC";
         harness.check(exp.equals(Util.toString(md)), "testABC");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.testABC");
      }

      try {
         algorithm = new RipeMD160();
         algorithm.update("message digest".getBytes(), 0, 14);
         byte[] md = algorithm.digest();
         String exp = "5D0689EF49D2FAE572B881B123A85FFA21595F36";
         harness.check(exp.equals(Util.toString(md)), "testMessageDigest");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.testMessageDigest");
      }

      try {
         algorithm = new RipeMD160();
         algorithm.update("abcdefghijklmnopqrstuvwxyz".getBytes(), 0, 26);
         byte[] md = algorithm.digest();
         String exp = "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC";
         harness.check(exp.equals(Util.toString(md)), "testAlphabet");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.testAlphabet");
      }

      try {
         algorithm = new RipeMD160();
         algorithm.update("a".getBytes(), 0, 1);
         clone = (IMessageDigest) algorithm.clone();
         byte[] md = algorithm.digest();
         String exp = "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE";
         harness.check(exp.equals(Util.toString(md)), "testCloning #1");

         clone.update("bc".getBytes(), 0, 2);
         md = clone.digest();
         exp = "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC";
         harness.check(exp.equals(Util.toString(md)), "testCloning #2");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfRipeMD160.testCloning");
      }
   }
}
