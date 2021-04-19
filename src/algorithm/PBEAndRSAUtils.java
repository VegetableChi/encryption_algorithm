package algorithm;

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PBEAndRSAUtils {

    /**
     * 输入密码，生成加密后密钥对和盐
     * @param password
     * @return
     * @throws Exception
     */
    public static Map<String,String> generateKeyPairByRSAAndPBE(String password) throws Exception {
        //生成RSA密钥对
        KeyPair keyPair = RSAUtils.getKeyPair(password);
        //获取RSA算法私钥
        byte[] privateKeyBytes = RSAUtils.getPrivateKeyBytes(keyPair);
        //生成随机数盐
        byte[] salt = PBEUtils.initSalt();
        //对RSA私钥进行加密
        byte[] encryptRSA_prk = PBEUtils.encrypt(privateKeyBytes, password, salt);
        //返回盐和新密钥对
        Map<String,String> returnKeyPairMessage = new HashMap<>();
        returnKeyPairMessage.put("puk",RSAUtils.getPublicKey(keyPair));
        returnKeyPairMessage.put("prk",byteToString(encryptRSA_prk));
        returnKeyPairMessage.put("salt",byteToString(salt));
        return returnKeyPairMessage;
    }

    /**
     * 利用RSA算法进行公钥加密
     * @param data 明文
     * @param puk
     * @return
     */
    public static String encryptByRSAAndPBE(String data, String puk) throws Exception {
        return RSAUtils.encryptByPublicKey(data,puk);
    }

    /**
     * 密码+私钥+盐 解密
     * @param password
     * @param salt
     * @param prk
     * @param encryptMessage
     * @return
     * @throws Exception
     */
    public static String decryptByRSAAndPBE(String password,byte[] salt,String prk,String encryptMessage) throws Exception {
        byte[] RSA_real_prk = PBEUtils.decrypt(stringToByte(prk), password, salt);
        byte[] realMessage = null;
        if(RSA_real_prk != null){
            realMessage = RSAUtils.decryptByPrivateKey(Base64.getDecoder().decode(encryptMessage), RSA_real_prk);
        }
        return realMessage == null ? null:new String(realMessage);
    }

    /**
     * byte 转 String
     * @param resouce
     * @return
     */
    public static String byteToString(byte[] resouce){
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < resouce.length; i++) {
            if (i == resouce.length-1) {
                sb.append(Byte.toString(resouce[i]));
            }else{
                sb.append(Byte.toString(resouce[i]));
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * String 转 byte
     * @param resouce
     * @return
     */
    public static byte[] stringToByte(String resouce){
        String[] strArr = resouce.split(" ");
        int len = strArr.length;
        byte[] clone = new byte[len];
        for (int i = 0; i < len; i++) {
            clone[i] = Byte.parseByte(strArr[i]);
        }
        return clone;
    }

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        System.out.println("请输入密码 生成密钥对");
        String password = in.next();
        Map<String, String> keyPairMessageMap = generateKeyPairByRSAAndPBE(password);
        System.out.println("生成密钥对信息为："+ keyPairMessageMap);

        System.out.println("请输入需要加密的数据");
        String data = in.next();

        String encryptMessage = encryptByRSAAndPBE(data, keyPairMessageMap.get("puk"));
        System.out.println("加密后数据为:"+encryptMessage);

        System.out.println("==========================");
        System.out.println("开始解密");

        System.out.println("请输入密码");
        String realMessage = decryptByRSAAndPBE(in.next(), stringToByte(keyPairMessageMap.get("salt")), keyPairMessageMap.get("prk"), encryptMessage);

        if(realMessage == null){
            System.out.println("解密失败");
        }else{
            System.out.println("真实数据为："+realMessage);
        }
    }
}
