package server;

import algorithm.RSAUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

public class Alice {
    public static void main(String[] args) throws Exception {
        ServerSocket clientSocket = new ServerSocket(8888);
        Socket accept = clientSocket.accept();
        InputStream inputStream = accept.getInputStream();
        OutputStream outputStream = accept.getOutputStream();

        DataInputStream dis = new DataInputStream(inputStream);
        DataOutputStream dos = new DataOutputStream(outputStream);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        KeyPair Alice_keyPair = RSAUtils.getKeyPair();
        String Alice_puk = RSAUtils.getPublicKey(Alice_keyPair);
        String Alice_prk = RSAUtils.getPrivateKey(Alice_keyPair);
        System.out.println("Alice:我的公钥为 " + Alice_puk);
        System.out.println("Alice:我的私钥为 " + Alice_prk);

        System.out.println("==========================");

        String Bob_puk = dis.readUTF();
        System.out.println("Bob:给你这是我的公钥:" + Bob_puk);
        dos.writeUTF(Alice_puk);
        while (true) {
            String info = dis.readUTF();
            String realMessage = RSAUtils.decryptByPrivateKey(info, Alice_prk);
            System.out.print("Bob说:" + realMessage + "  (密文为:" + info + ")\n");
            if (info.equals("bye")) {
                break;
            }
            System.out.print("Alice:");
            String encryptMessage = RSAUtils.encryptByPublicKey(br.readLine(), Bob_puk);
            dos.writeUTF(encryptMessage);
            System.out.println();
        }
        br.close();
        dos.close();
        dis.close();
    }
}
