package me.hello;
/*************************************************************************
    > File Name: test.java
    > Author: wayne
    > Mail: @163.com 
    > Created Time: 2015/6/4 16:59:19
 ************************************************************************/
/**
Copyright (c) 2011 IETF Trust and the persons identified as
authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in Section
4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
(http://trustee.ietf.org/license-info).
 */

import java.io.UnsupportedEncodingException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.TimeZone;

/**
 * This is an example implementation of the OATH TOTP algorithm. Visit
 * www.openauthentication.org for more information.
 * 
 * @author Johan Rydell, PortWise, Inc.
 */


public class TOTP {

    private TOTP() {
    }
    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a
     * Hashed Message Authentication Code with the crypto hash algorithm as a
     * parameter.
     * 
     * @param crypto
     *            : the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes
     *            : the bytes to use for the HMAC key
     * @param text
     *            : the message or text to be authenticated
     */
    
//    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
//        try {
//            Mac hmac;
//            hmac = Mac.getInstance(crypto);
//            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
//            hmac.init(macKey);
//            return hmac.doFinal(text);
//        } catch (GeneralSecurityException gse) {
//            throw new UndeclaredThrowableException(gse);
//        }
//    }
//    
    
    private static byte[] hmacDigest(String msg, String keyString, String algo) {
    	byte[] digest = null;
        try {
        	System.out.println((keyString).getBytes("UTF-8"));
          SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo);
          Mac mac = Mac.getInstance(algo);
          mac.init(key);

          byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));

          StringBuffer hash = new StringBuffer();
          for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
              hash.append('0');
            }
            hash.append(hex);
          }
          //digest = hash.toString();
          digest = bytes;
        } catch (UnsupportedEncodingException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }
        return digest;
      }
    

    /**
     * This method converts a HEX string to Byte[]
     * 
     * @param hex
     *            : the HEX string
     * 
     * @return: a byte array
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final int[] DIGITS_POWER
    // 0 1 2 3 4 5 6 7 8
    = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /**
     * This method generates a TOTP value for the given set of parameters.
     * 
     * @param key
     *            : the shared secret, HEX encoded
     * @param time
     *            : a value that reflects a time
     * @param returnDigits
     *            : number of digits to return
     * 
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP(String key, String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }
    
    /* *
     * Convert byte[] to hex string.这里我们可以将byte转换成int，然后利用Integer.toHexString(int)
     *来转换成16进制字符串。  
     * @param src byte[] data  
     * @return hex string  
     */     
    public static String bytesToHexString(byte[] src){  
        StringBuilder stringBuilder = new StringBuilder("");  
        if (src == null || src.length <= 0) {  
            return null;  
        }  
        for (int i = 0; i < src.length; i++) {  
            int v = src[i] & 0xFF;  
            String hv = Integer.toHexString(v);  
            if (hv.length() < 2) {  
                stringBuilder.append(0);  
            }  
            stringBuilder.append(hv);  
        }  
        return stringBuilder.toString();  
    }  

    /**
     * This method generates a TOTP value for the given set of parameters.
     * 
     * @param key
     *            : the shared secret, HEX encoded
     * @param time
     *            : a value that reflects a time
     * @param returnDigits
     *            : number of digits to return
     * 
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP256(String key, String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    /**
     * This method generates a TOTP value for the given set of parameters.
     * 
     * @param key
     *            : the shared secret, HEX encoded
     * @param time
     *            : a value that reflects a time
     * @param returnDigits
     *            : number of digits to return
     * 
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP512(String key, String time,
            String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    /**
     * This method generates a TOTP value for the given set of parameters.
     * 
     * @param key
     *            : the shared secret, HEX encoded
     * @param time
     *            : a value that reflects a time
     * @param returnDigits
     *            : number of digits to return
     * @param crypto
     *            : the crypto function to use
     * 
     * @return: a numeric String in base 10 that includes
     *          {@link truncationDigits} digits
     */

    public static String generateTOTP(String key, String time,
            String returnDigits, String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)

//        while (time.length() < 16)
//            time = "0" + time;
        System.out.println("---- time hash is:"+time);

        // Get the HEX in a Bye[]

        
        //byte[] msg = hexStr2Bytes(time);
        //byte[] k = hexStr2Bytes(key);
        //byte[] hash = hmac_sha(crypto, k, msg);
        byte[] hash = hmacDigest(time,key,crypto);
        System.out.println("---- byte hash is:"+hash);
        System.out.println("---- hex  is:"+bytesToHexString(hash));

        // put selected bytes into result int
        
        
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    public static void main(String[] args) {
        String key = "123";
//      String time = "47782269";
        new Date().getTime();
        long cur_time_second;
        System.out.println(System.currentTimeMillis()/30000);
        cur_time_second = System.currentTimeMillis()/30000;
        String time = Long.toString(cur_time_second);
        
        byte[] hash1 = hmacDigest(time ,key, "HmacSHA1");
        System.out.println("---- hex  is:"+bytesToHexString(hash1));
        
        System.out.println( generateTOTP(key, time, "6", "HmacSHA1"));
    }
}
