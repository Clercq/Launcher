package pro.gravit.launchserver.socket.response.update;

import io.netty.channel.ChannelHandlerContext;
import pro.gravit.launcher.events.request.LauncherRequestEvent;
import pro.gravit.launchserver.socket.Client;
import pro.gravit.launchserver.socket.response.SimpleResponse;
import pro.gravit.utils.Version;
import pro.gravit.utils.helper.SecurityHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class LauncherResponse extends SimpleResponse {
    public Version version;
    public String hash;
    public byte[] digest;
    public int launcher_type;

    public String secureHash;
    public String secureSalt;

    @Override
    public String getType() {
        return "launcher";
    }

    @Override
    public void execute(ChannelHandlerContext ctx, Client client) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        byte[] bytes;
        if (hash != null)
            bytes = Base64.getDecoder().decode(hash);
        else
            bytes = digest;
        if (launcher_type == 1) // JAR
        {
            byte[] hash = server.launcherBinary.getDigest();
            if (hash == null)
                service.sendObjectAndClose(ctx, new LauncherRequestEvent(true, server.config.netty.launcherURL));
            if (Arrays.equals(bytes, hash) && checkSecure(secureHash, secureSalt)) {
                client.checkSign = true;
                sendResult(new LauncherRequestEvent(false, server.config.netty.launcherURL));
            } else {
                sendResultAndClose(new LauncherRequestEvent(true, server.config.netty.launcherURL));
            }
        } else if (launcher_type == 2) //EXE
        {
            byte[] hash = server.launcherEXEBinary.getDigest();
            if (hash == null) sendResultAndClose(new LauncherRequestEvent(true, server.config.netty.launcherEXEURL));
            if (Arrays.equals(bytes, hash) && checkSecure(secureHash, secureSalt)) {
                client.checkSign = true;
                sendResult(new LauncherRequestEvent(false, server.config.netty.launcherEXEURL));
            } else {
                sendResultAndClose(new LauncherRequestEvent(true, server.config.netty.launcherEXEURL));
            }
        } else if (launcher_type == 228) // UWP & WPF
        {
            if (!secureHash.equals("") && secureSalt.equals("")) {
                System.out.println(secureHash);
                byte[] aesDecrypted = AESDecrypt(secureHash);
                System.out.println(Base64.getEncoder().encodeToString(aesDecrypted));
                byte[] signature = new byte[64];
                byte[] XORKey = new byte[16];
                System.arraycopy(aesDecrypted, 0, signature, 0, 64);
                System.arraycopy(aesDecrypted, 64, XORKey, 0, 16);
                System.out.println(Base64.getEncoder().encodeToString(signature));
                System.out.println(Base64.getEncoder().encodeToString(XORKey));

                String signatureEncoded = new String(signature, StandardCharsets.UTF_8);
                System.out.println(sha256Encrypt(XORCrypto(XORKey)));
                if (signatureEncoded.equalsIgnoreCase(sha256Encrypt(XORCrypto(XORKey)))) {
                    client.checkSign = true;
                    sendResult(new LauncherRequestEvent(false, server.config.netty.launcherEXEURL));
                } else {
                    sendResultAndClose(new LauncherRequestEvent(true, server.config.netty.launcherEXEURL));
                }
            } else {
                sendError("Request launcher type error");
            }
        } else sendError("Request launcher type error");
    }

    private boolean checkSecure(String hash, String salt) {
        if (hash == null || salt == null) return false;
        byte[] normal_hash = SecurityHelper.digest(SecurityHelper.DigestAlgorithm.SHA256,
                server.runtime.clientCheckSecret.concat(".").concat(salt));
        byte[] launcher_hash = Base64.getDecoder().decode(hash);
        return Arrays.equals(normal_hash, launcher_hash);
    }

    private String sha256Encrypt(byte[] chlen) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(chlen);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02X", b));
        }
        System.out.println(sb.toString().toLowerCase());
        return sb.toString().toLowerCase();
    }

    private byte[] XORCrypto(byte[] XORKey){
        byte[] result = new byte[16];
        byte[] secret = new String("9pwGwCjcasRfHWCh").getBytes();
        //XOR Decode
        for (int i = 0; i < XORKey.length; i++)
        {
            result[i] = (byte)(secret[i] ^ XORKey[i]);
        }
        System.out.println(Base64.getEncoder().encodeToString(result));
        return result;
    }

    private byte[] AESDecrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] decoded = Base64.getDecoder().decode(data);
        byte[] keyDecoded = Base64.getDecoder().decode("7s0Vg0yQrc9iyLCqXmwByQ==");
        SecretKeySpec sKeySpec = new SecretKeySpec(keyDecoded, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec);
        return cipher.doFinal(decoded);
    }

}
