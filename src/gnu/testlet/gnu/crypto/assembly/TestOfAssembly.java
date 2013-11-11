package gnu.testlet.gnu.crypto.assembly;

// ----------------------------------------------------------------------------
// $Id: TestOfAssembly.java,v 1.4 2005/10/06 04:24:19 rsdio Exp $
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

import gnu.crypto.Registry;
import gnu.crypto.assembly.Assembly;
import gnu.crypto.assembly.Cascade;
import gnu.crypto.assembly.Direction;
import gnu.crypto.assembly.Stage;
import gnu.crypto.assembly.Transformer;
import gnu.crypto.assembly.TransformerException;
import gnu.crypto.cipher.Blowfish;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.pad.IPad;
import gnu.crypto.pad.PadFactory;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Simple symmetry tests for 3 assembly constructions.</p>
 *
 * @version $Revision: 1.4 $
 */
public class TestOfAssembly implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private Assembly asm;
   private HashMap attributes = new HashMap();
   private HashMap modeAttributes = new HashMap();

   // Constructor(s)
   // -------------------------------------------------------------------------

   public TestOfAssembly() {
      super();
   }

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      TestOfAssembly testcase = new TestOfAssembly();

      // build an OFB-Blowfish cascade
      Cascade ofbBlowfish = new Cascade();
      Object modeNdx = ofbBlowfish.append(
            Stage.getInstance(
                  ModeFactory.getInstance(Registry.OFB_MODE, new Blowfish(), 8),
                  Direction.FORWARD));

      testcase.attributes.put(modeNdx, testcase.modeAttributes);

      IPad pkcs7 = PadFactory.getInstance(Registry.PKCS7_PAD);

      testcase.asm = new Assembly();
      testcase.asm.addPreTransformer(Transformer.getCascadeTransformer(ofbBlowfish));
      testcase.asm.addPreTransformer(Transformer.getPaddingTransformer(pkcs7));

      testcase.testSymmetry(harness, 1);

      // add a compression transformer.
      // the resulting assembly encrypts + pad first and compresses later
//      testcase.asm = new Assembly();
//      testcase.asm.addPreTransformer(Transformer.getCascadeTransformer(ofbBlowfish));
//      testcase.asm.addPreTransformer(Transformer.getPaddingTransformer(pkcs7));
      testcase.asm.addPostTransformer(Transformer.getDeflateTransformer());

      testcase.testSymmetry(harness, 2);

      // now build an assembly that compresses first and encrypts + pads later
      testcase.asm = new Assembly();
      testcase.asm.addPreTransformer(Transformer.getCascadeTransformer(ofbBlowfish));
      testcase.asm.addPreTransformer(Transformer.getPaddingTransformer(pkcs7));
      testcase.asm.addPreTransformer(Transformer.getDeflateTransformer());

      testcase.testSymmetry(harness, 3);
   }

   private void testSymmetry(TestHarness harness, int ndx) {
      harness.checkPoint("TestOfAssembly.testSymmetry#"+ndx);

      byte[] km = new byte[] { 0,  1,  2,  3,  4,  5,  6,  7,  8};
      byte[] iv = new byte[] {-1, -2, -3, -4, -5, -6, -7, -8, -9};
      byte[] pt = new byte[] { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,  11};
      byte[] tpt = new byte[11 * pt.length];

      // forward
      modeAttributes.put(IBlockCipher.KEY_MATERIAL, km);
      modeAttributes.put(IMode.IV, iv);
      attributes.put(Assembly.DIRECTION, Direction.FORWARD);
      try {
         asm.init(attributes);
      } catch (TransformerException x) {
         harness.debug(x);
         harness.fail("Forward initialisation");
         return;
      }

      byte[] ct = null;
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try {
         for (int i = 0; i < 10; i++) { // transform in parts of 12-byte a time
            System.arraycopy(pt, 0, tpt, i * pt.length, pt.length);
            ct = asm.update(pt);
            baos.write(ct, 0, ct.length);
         }
      } catch (TransformerException x) {
         harness.debug(x);
         harness.fail("Forward transformation");
         return;
      }
      try {
         System.arraycopy(pt, 0, tpt, 10 * pt.length, pt.length);
         ct = asm.lastUpdate(pt);
      } catch (TransformerException x) {
         harness.debug(x);
         harness.fail("Forward last transformation");
         return;
      }
      baos.write(ct, 0, ct.length);
      ct = baos.toByteArray();

      // reversed
      attributes.put(Assembly.DIRECTION, Direction.REVERSED);
      try {
         asm.init(attributes);
      } catch (TransformerException x) {
         harness.debug(x);
         harness.fail("Reverse initialisation");
         return;
      }

      byte[] ot;
      try {
         ot = asm.lastUpdate(ct); // transform the lot in one go
      } catch (TransformerException x) {
         harness.debug(x);
         harness.fail("Reverse transformation");
         return;
      }

      harness.check(Arrays.equals(ot, tpt), "symmetric test");
   }
}
