package client;

import algorithm.RSAUtils;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("127.0.0.1", 8888);
        Scanner scanner = new Scanner(System.in);

        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();

        DataOutputStream dos = new DataOutputStream(outputStream);
        DataInputStream dis = new DataInputStream(inputStream);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        KeyPair Bob_keyPair = RSAUtils.getKeyPair();
        String Bob_puk = RSAUtils.getPublicKey(Bob_keyPair);
        String Bob_prk = RSAUtils.getPrivateKey(Bob_keyPair);
        System.out.println("Bob:我的公钥为 " + Bob_puk);
        System.out.println("Bob:我的私钥为 " + Bob_prk);

        System.out.println("==========================");

        dos.writeUTF(Bob_puk);

        String Alice_puk = dis.readUTF();
        System.out.println("Alice:给你这是我的公钥:" + Alice_puk);

        while (true) {
            System.out.print("Bob：");
            String message = br.readLine();
            System.out.println();
            String encryptMessage = RSAUtils.encryptByPublicKey(message, Alice_puk);
            dos.writeUTF(encryptMessage);
            if (message.equals("bye"))
                break;
            message = dis.readUTF();
            String realMessage = RSAUtils.decryptByPrivateKey(message, Bob_prk);
            System.out.print("Alice说:" + realMessage + "  (密文为:" + message + ")\n");
        }
        br.close();
        dos.close();
        dis.close();
    }
}
