package algorithm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class DESUtils {
    /**
     * 测试方法
     */
    public static void main(String[] args) {
        String str = "你好,goldlone";

        String password = "12345678";

        String encryStr =  DESUtils.encrypt(str, password);
        System.out.println("加密结果："+encryStr);

        String decryStr = DESUtils.decrypt(encryStr, password);
        System.out.println("解密结果："+decryStr);
    }

    /**
     * 进行加密操作
     * 参数一：待加密的字符串，参数二：加密密钥
     * 返回经过Base64编码后的字符串
     * 编码格式为UTF-8
     */
    public static String encrypt(String encryptionStr, String password) {
        try{
            byte[] encryptionBytes = encryptionStr.getBytes("UTF-8");
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(password.getBytes());
            // 创建一个密钥工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secureKey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密钥初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, secureKey, random);
            // 执行加密操作
            byte[] encryptionBase64Bytes = Base64.getEncoder().encode(cipher.doFinal(encryptionBytes));
            // 转换为字符串返回
            return new String(encryptionBase64Bytes);
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 进行解密操作
     * 参数一：待解密的字符串，参数二：加密密钥
     * 返回解密后的字符串
     */
    public static String decrypt(String decryptionBase64Str, String password) {
        try {
            byte[] decryptionbytes = Base64.getDecoder().decode(decryptionBase64Str);
            // DES算法要求有一个可信任的随机数源
            SecureRandom random = new SecureRandom();
            // 创建一个DESKeySpec对象
            DESKeySpec desKey = new DESKeySpec(password.getBytes());
            // 创建一个密钥工厂
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // 将DESKeySpec对象转换成SecretKey对象
            SecretKey securekey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成解密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密钥初始化Cipher对象
            cipher.init(Cipher.DECRYPT_MODE, securekey, random);
            // 开始解密操作
            return new String(cipher.doFinal(decryptionbytes), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
