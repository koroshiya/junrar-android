package gnu.testlet.gnu.crypto.mode;

// ----------------------------------------------------------------------------
// $Id: TestOfModeFactory.java,v 1.2 2005/10/06 04:24:20 rsdio Exp $
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

import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.mode.IMode;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;
import java.util.Iterator;

/**
 * Conformance tests for the ModeFactory implementation.
 *
 * @version $Revision: 1.2 $
 */
public class TestOfModeFactory implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfModeFactory");
      String mode, cipher;
      int bs;
      IMode algorithm;
      for (Iterator mit = ModeFactory.getNames().iterator(); mit.hasNext(); ) {
         mode = (String) mit.next();
         for (Iterator cit = CipherFactory.getNames().iterator(); cit.hasNext(); ) {
            cipher = (String) cit.next();
            IBlockCipher ubc = CipherFactory.getInstance(cipher);
            for (Iterator cbs = ubc.blockSizes(); cbs.hasNext(); ) {
               bs = ((Integer) cbs.next()).intValue();
               try {
                  algorithm = ModeFactory.getInstance(mode, ubc, bs);
                  harness.check(algorithm != null, "getInstance("
                        +String.valueOf(mode)+", "
                        +String.valueOf(cipher)+", "
                        +String.valueOf(8*bs)+")");
               } catch (InternalError x) {
                  harness.debug(x);
                  harness.fail("TestOfModeFactory.getInstance("
                        +String.valueOf(mode)+", "
                        +String.valueOf(cipher)+", "
                        +String.valueOf(8*bs)+")");
               }
            }
         }
      }
   }
}
