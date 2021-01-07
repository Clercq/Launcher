package pro.gravit.launcher;

import pro.gravit.launcher.client.*;
import pro.gravit.launcher.client.events.ClientEngineInitPhase;
import pro.gravit.launcher.client.events.ClientExitPhase;
import pro.gravit.launcher.client.events.ClientPreGuiPhase;
import pro.gravit.launcher.guard.LauncherGuardInterface;
import pro.gravit.launcher.guard.LauncherGuardManager;
import pro.gravit.launcher.guard.LauncherNoGuard;
import pro.gravit.launcher.guard.LauncherWrapperGuard;
import pro.gravit.launcher.gui.NoRuntimeProvider;
import pro.gravit.launcher.gui.RuntimeProvider;
import pro.gravit.launcher.managers.ClientGsonManager;
import pro.gravit.launcher.managers.ConsoleManager;
import pro.gravit.launcher.modules.events.PreConfigPhase;
import pro.gravit.launcher.profiles.optional.actions.OptionalAction;
import pro.gravit.launcher.request.Request;
import pro.gravit.launcher.request.RequestException;
import pro.gravit.launcher.request.auth.AuthRequest;
import pro.gravit.launcher.request.auth.RestoreSessionRequest;
import pro.gravit.launcher.request.websockets.StdWebSocketService;
import pro.gravit.launcher.utils.NativeJVMHalt;
import pro.gravit.utils.helper.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

public class LauncherEngine {
    public static final AtomicBoolean IS_CLIENT = new AtomicBoolean(false);
    public static ClientLauncherProcess.ClientParams clientParams;
    public static LauncherGuardInterface guard;
    public static ClientModuleManager modulesManager;
    // Instance
    private final AtomicBoolean started = new AtomicBoolean(false);
    public RuntimeProvider runtimeProvider;
    public ECPublicKey publicKey;
    public ECPrivateKey privateKey;
    //Clercqer Let's Ecnrypt Support

    private static TrustManagerFactory tmf;

    public static TrustManagerFactory getTrastManagerFucktory(){
        return tmf;
    }

    static {
        try {
            LogHelper.info("Starting injecting PolitCubes certificate for @deprecated Java");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            Path ksPath = Paths.get(System.getProperty("java.home"),
                    "lib", "security", "cacerts");
            keyStore.load(Files.newInputStream(ksPath),
                    "changeit".toCharArray());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (InputStream caInput = new ByteArrayInputStream(new String("-----BEGIN CERTIFICATE-----\n" +
                    "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n" +
                    "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
                    "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n" +
                    "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n" +
                    "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                    "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n" +
                    "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n" +
                    "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n" +
                    "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n" +
                    "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n" +
                    "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n" +
                    "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n" +
                    "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n" +
                    "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n" +
                    "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n" +
                    "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n" +
                    "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n" +
                    "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n" +
                    "-----END CERTIFICATE-----").getBytes())) {
                Certificate crt = cf.generateCertificate(caInput);
                LogHelper.debug("Added Cert for " + ((X509Certificate) crt)
                        .getSubjectDN());

                keyStore.setCertificateEntry("letsEncrypt", crt);
            }

            tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            SSLContext.setDefault(sslContext);
            LogHelper.info("Successfully injected for CORE module");
        } catch (Exception e) {
            LogHelper.debug("Something went wrong. The CA wasn't added.");
        }
    }

    private LauncherEngine() {

    }

    //JVMHelper.getCertificates
    public static X509Certificate[] getCertificates(Class<?> clazz) {
        Object[] signers = clazz.getSigners();
        if (signers == null) return null;
        return Arrays.stream(signers).filter((c) -> c instanceof X509Certificate).map((c) -> (X509Certificate) c).toArray(X509Certificate[]::new);
    }

    public static void checkClass(Class<?> clazz) throws SecurityException {
        LauncherTrustManager trustManager = Launcher.getConfig().trustManager;
        if (trustManager == null) return;
        X509Certificate[] certificates = getCertificates(clazz);
        if (certificates == null) {
            throw new SecurityException(String.format("Class %s not signed", clazz.getName()));
        }
        try {
            trustManager.checkCertificate(certificates, trustManager::stdCertificateChecker);
        } catch (CertificateException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SecurityException(e);
        }
    }

    public static void exitLauncher(int code) {
        modulesManager.invokeEvent(new ClientExitPhase(code));
        try {
            System.exit(code);
        } catch (Throwable e) //Forge Security Manager?
        {
            NativeJVMHalt.haltA(code);
        }
    }

    public static void main(String... args) throws Throwable {
        JVMHelper.checkStackTrace(LauncherEngine.class);
        JVMHelper.verifySystemProperties(Launcher.class, true);
        EnvHelper.checkDangerousParams();
        //if(!LauncherAgent.isStarted()) throw new SecurityException("JavaAgent not set");
        verifyNoAgent();
        LogHelper.printVersion("Launcher");
        LogHelper.printLicense("Launcher");
        LauncherEngine.checkClass(LauncherEngine.class);
        LauncherEngine.checkClass(LauncherAgent.class);
        LauncherEngine.checkClass(ClientLauncherEntryPoint.class);
        LauncherEngine.modulesManager = new ClientModuleManager();
        LauncherEngine.modulesManager.loadModule(new ClientLauncherCoreModule());
        LauncherConfig.initModules(LauncherEngine.modulesManager);
        LauncherEngine.modulesManager.initModules(null);
        // Start Launcher
        initGson(LauncherEngine.modulesManager);
        ConsoleManager.initConsole();
        LauncherEngine.modulesManager.invokeEvent(new PreConfigPhase());
        Launcher.getConfig(); // init config
        long startTime = System.currentTimeMillis();
        try {
            new LauncherEngine().start(args);
        } catch (Exception e) {
            LogHelper.error(e);
            return;
        }
        long endTime = System.currentTimeMillis();
        LogHelper.debug("Launcher started in %dms", endTime - startTime);
        //Request.service.close();
        //FunctionalBridge.close();
        LauncherEngine.exitLauncher(0);
    }

    public static void initGson(ClientModuleManager modulesManager) {
        AuthRequest.registerProviders();
        OptionalAction.registerProviders();
        Launcher.gsonManager = new ClientGsonManager(modulesManager);
        Launcher.gsonManager.initGson();
    }

    public static void verifyNoAgent() {
        if (JVMHelper.RUNTIME_MXBEAN.getInputArguments().stream().filter(e -> e != null && !e.isEmpty()).anyMatch(e -> e.contains("javaagent")))
            throw new SecurityException("JavaAgent found");
    }

    public static LauncherGuardInterface tryGetStdGuard() {
        switch (Launcher.getConfig().guardType) {
            case "no":
                return new LauncherNoGuard();
            case "wrapper":
                return new LauncherWrapperGuard();
        }
        return null;
    }

    public static LauncherEngine clientInstance() {
        return new LauncherEngine();
    }

    public void readKeys() throws IOException, InvalidKeySpecException {
        if (privateKey != null || publicKey != null) return;
        Path dir = DirBridge.dir;
        Path publicKeyFile = dir.resolve("public.key");
        Path privateKeyFile = dir.resolve("private.key");
        if (IOHelper.isFile(publicKeyFile) && IOHelper.isFile(privateKeyFile)) {
            LogHelper.info("Reading EC keypair");
            publicKey = SecurityHelper.toPublicECKey(IOHelper.read(publicKeyFile));
            privateKey = SecurityHelper.toPrivateECKey(IOHelper.read(privateKeyFile));
        } else {
            LogHelper.info("Generating EC keypair");
            KeyPair pair = SecurityHelper.genECKeyPair(new SecureRandom());
            publicKey = (ECPublicKey) pair.getPublic();
            privateKey = (ECPrivateKey) pair.getPrivate();

            // Write key pair list
            LogHelper.info("Writing EC keypair list");
            IOHelper.write(publicKeyFile, publicKey.getEncoded());
            IOHelper.write(privateKeyFile, privateKey.getEncoded());
        }
    }

    public void start(String... args) throws Throwable {
        //Launcher.modulesManager = new ClientModuleManager(this);
        LauncherEngine.guard = tryGetStdGuard();
        ClientPreGuiPhase event = new ClientPreGuiPhase(null);
        LauncherEngine.modulesManager.invokeEvent(event);
        runtimeProvider = event.runtimeProvider;
        if (runtimeProvider == null) runtimeProvider = new NoRuntimeProvider();
        runtimeProvider.init(false);
        //runtimeProvider.preLoad();
        if (Request.service == null) {
            String address = Launcher.getConfig().address;
            LogHelper.debug("Start async connection to %s", address);
            Request.service = StdWebSocketService.initWebSockets(address, true);
            Request.service.reconnectCallback = () ->
            {
                LogHelper.debug("WebSocket connect closed. Try reconnect");
                try {
                    Request.service.open();
                    LogHelper.debug("Connect to %s", Launcher.getConfig().address);
                } catch (Exception e) {
                    LogHelper.error(e);
                    throw new RequestException(String.format("Connect error: %s", e.getMessage() != null ? e.getMessage() : "null"));
                }
                try {
                    RestoreSessionRequest request1 = new RestoreSessionRequest(Request.getSession());
                    request1.request();
                } catch (Exception e) {
                    LogHelper.error(e);
                }
            };
        }
        Objects.requireNonNull(args, "args");
        if (started.getAndSet(true))
            throw new IllegalStateException("Launcher has been already started");
        readKeys();
        LauncherEngine.modulesManager.invokeEvent(new ClientEngineInitPhase(this));
        runtimeProvider.preLoad();
        LauncherGuardManager.initGuard(false);
        LogHelper.debug("Dir: %s", DirBridge.dir);
        runtimeProvider.run(args);
    }
}
