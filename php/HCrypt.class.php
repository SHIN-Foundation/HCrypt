<?php set_time_limit(0);
  /*	
   *	HCrypt - PHP Class ` All in One `
   *	>_ No dependencies
   *	
   *	Written in 2018 by
   *	Mr. Shin Hako　「箱新さん」 AND 
   *	Ms. Yoshino Abe　「阿部吉野さん」
   *	=======================================================
   *	箱さんと阿部さんはSHINCOINのニーズを　
   *	満たすためにこのアルゴリズムを開発しました。　
   *	<< https://shin-foundation.github.io >>
   *	
   *	===  MIT License  ===
   *	Copyright (c) 2018 Shin Foundation
   *	
   *	Permission is hereby granted, free of charge, to any person obtaining a copy
   *	of this software and associated documentation files (the "Software"), to deal
   *	in the Software without restriction, including without limitation the rights
   *	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   *	copies of the Software, and to permit persons to whom the Software is
   *	furnished to do so, subject to the following conditions:
   *	
   *	The above copyright notice and this permission notice shall be included in all
   *	copies or substantial portions of the Software.
   *	
   *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   *	SOFTWARE.
   *
   */
   
  Class HCrypt
  {

    function _crypt ($_data='', $_jump=4, $_prefix='', $_salt='' )
    {

      // If data is empty, return 'n/a'.
      if ( $_data == null )
      {
        return 'n/a';
      }

      // If jump is <= 4, calcules 2^4. If is >= 16, calcules 2^16.
      // Calcules between 4 and 16 your power of two.
      if ( $_jump >= 4 && $_jump <= 16 )
      {
        $r_jump = pow ( 2, $_jump );
      }
      if ( $_jump > 16 )
      {
        $r_jump = pow ( 2, 16 );
        $_jump = '16';
      }
      if ( $_jump < 4 )
      {
        $r_jump = pow ( 2, 4 );
        $_jump = '04';
      }
      if ( strlen ( $_jump ) < 2 )
      {
        $_jump = '0' . $_jump;
      }

      // This is an array of hex jumper, works as salt auxiliary.
      $wolf = array (
        // JPnese
        0x5b50, 0x7f8a, 0x3001, 0x306a, 0x3093, 0x304b,
        0x8a71, 0x3057, 0x3066, 0x304f, 0x308c, 0x3002,
        0x50d5, 0x306e, 0x540d, 0x306f, 0x30b9, 0x30c9,
        0x30bd, 0x30f3, 0x3060, 0xff01, 0x79c1, 0x306e,
        0x30b3, 0x30fc, 0x30c9, 0x30cd, 0x30fc, 0x30e0,
        0x306f, 0x7bb1, 0x65b0, 0x3068, 0x963f, 0x90e8,
        0x5409, 0x91ce, 0x3067, 0x3059, 0x3088, 0x3002
      );

      // Converts the first character in hexadecimal prefix.
      $_prefix_dec = ord ( strtoupper ( $_prefix[0] ) );
      $_prefix_hex = '0x' . dechex ( $_prefix_dec );
      if (
        $_prefix_hex == $_prefix_dec &&           // If decimal value is compatible with hex value
        $_prefix_hex != 0x0 &&                    // If hex value is not null
        strlen ( $_prefix_hex ) == 4 &&           // If prefix len is 4
        preg_match ( "/^[A-Z]+$/", $_prefix[0] )  // If input is an alphabet
      )
      {
        $r_prefix = $_prefix_hex;
      } else {
        $r_prefix = '0x48';
      }

      // Ignore the rest if salt is declared and if has 22 characters alphanumeric
      $r_salt = $_salt;
      if( strlen ( $_salt ) != 22 || !preg_match ( "/^[a-zA-Z0-9]+$/", $_salt ) )
      {
        $r_salt = null;
        for ( $i = 0; $i < 22; $i++ )
        {
          $choose = mt_rand( 1, 3 );
          $coding = (
            ( $choose == 1 ) ? mt_rand ( 97, 122 ) : (
            ( $choose == 2 ) ? mt_rand ( 65, 90 ): mt_rand ( 48, 57 ) )
          );
          $r_salt .= chr ( $coding );
        }
      }

      // Starts to digest
      $s = 0;         // Get the salt char
      $m = 0;         // Get the char of input data
      $msg = null;    // Concatenates the digest
      $qcalc = null;  // Sum the results of equation
      $repeat = true;

      while ( $repeat )
      {
        if ( $s > 22 ) { $s = 0; }
        $calc = ord ( $r_salt[$s] ) * ord ( $_data[$m] );
        while ( $calc > 42 )
        {
          $calc = floor ( $calc / 3 );
        }
        $pcalc = $r_jump * ( hexdec ( $wolf[$calc] ) + ord ( $r_salt[$s] ) );
        $digest = 1;
        $size_data = strlen ( $_data );
        for ( $pcr = 0; $pcr < 35; $pcr++ )
        {
          if ( $m > $size_data ) { $m = 0; }
          $digest = ( ord ( $_data[$m] ) + $digest ) / 16;
          $qcalc += $digest;
          $m++;
        }
        $s++;
        $aZzn = dechex ( $pcalc * ceil ( $qcalc ) );
        $aZzn = str_split ( $aZzn, 4 );
        for ( $xaz = 0; $xaz < count ( $aZzn ); $xaz++ )
        {
          $str_aZzn = null;
          $conv = $aZzn[$xaz];
          for ( $i = 0; $i < strlen ( $conv ) - 1; $i += 2 )
          {
            $str_aZzn .= chr ( hexdec ( $conv[$i] . $conv[$i + 1] ) );
          }
          if ( preg_match ( "/^[a-zA-Z0-9]+$/", $str_aZzn ) )
          {
            $msg .= preg_replace ( '/\s+/', '', $str_aZzn );
            $xaz = count ( $aZzn );
          }
        }
        if ( strlen ( $msg ) == 36 )
        {
          $repeat = false;
          return $r_prefix . $_jump . $msg . $r_salt;
        }
        if ( strlen ( $msg ) > 36 )
        {
          $repeat = false;
          $subthis = 36 - strlen ( $msg );
          return $r_prefix . $_jump . substr ( $msg, 0, $subthis ) . $r_salt;
        }
      }
    }
  }
