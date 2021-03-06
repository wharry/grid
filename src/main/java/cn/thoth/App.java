package cn.thoth;

import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.config.keys.DefaultAuthorizedKeysAuthenticator;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.InteractiveProcessShellFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.*;
import java.nio.file.Paths;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        System.setProperty("org.apache.sshd.common.io.IoServiceFactoryFactory", "org.apache.sshd.netty.NettyIoServiceFactoryFactory");
        final PortForwardingEventListener serverSideListener = new PortForwardingEventListener() {
            private final Logger log = LoggerFactory.getLogger(App.class);


            public void establishingExplicitTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                                                   SshdSocketAddress remote, boolean localForwarding) throws IOException {
                log.info("establishingExplicitTunnel(session={}, local={}, remote={}, localForwarding={})",
                        session, local, remote, localForwarding);
            }


            public void establishedExplicitTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                                                  SshdSocketAddress remote, boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
                    throws IOException {
                log.info("establishedExplicitTunnel(session={}, local={}, remote={}, bound={}, localForwarding={}): {}",
                        session, local, remote, boundAddress, localForwarding, reason);
            }


            public void tearingDownExplicitTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address,
                                                  boolean localForwarding) throws IOException {
                log.info("tearingDownExplicitTunnel(session={}, address={}, localForwarding={})", session, address, localForwarding);
            }


            public void tornDownExplicitTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address,
                                               boolean localForwarding, Throwable reason) throws IOException {
                log.info("tornDownExplicitTunnel(session={}, address={}, localForwarding={}, reason={})",
                        session, address, localForwarding, reason);
            }


            public void establishingDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local)
                    throws IOException {
                log.info("establishingDynamicTunnel(session={}, local={})", session, local);
            }


            public void establishedDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                                                 SshdSocketAddress boundAddress, Throwable reason) throws IOException {
                log.info("establishedDynamicTunnel(session={}, local={}, bound={}, reason={})", session, local, boundAddress, reason);
            }


            public void tearingDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address)
                    throws IOException {
                log.info("tearingDownDynamicTunnel(session={}, address={})", session, address);
            }


            public void tornDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address,
                                              Throwable reason) throws IOException {
                log.info("tornDownDynamicTunnel(session={}, address={}, reason={})", session, address, reason);
            }
        };
        System.out.println("Hello World!");
        IoServiceFactoryFactory ioProvider = getIoServiceProvider();
        System.out.println("Using default provider: " + ioProvider.getClass().getName());
        File file = getKeyFile();
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8080);

        //*give host key generator a path, when sshd server restart, the same key will be load and used to authenticate the server
        System.out.println(file.exists());
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(file));

        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {

            @Override
            public boolean authenticate(String u, String p, ServerSession s) {
                return ("sshtest".equals(u) && "sshtest".equals(p));
            }
        });
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        //sshd.setAgentFactory(new ProxyAgentFactory());
        //sshd.setShellFactory(new InteractiveProcessShellFactory());
        sshd.setShellFactory(new EchoShellFactory());
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.WINDOW_SIZE, 2048);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.MAX_PACKET_SIZE, "256");
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        //  sshd.addPortForwardingEventListener(serverSideListener);
        sshd.start();

        try {
            Thread.sleep(100000000000l);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


    }

    public static IoServiceFactoryFactory getIoServiceProvider() {
        DefaultIoServiceFactoryFactory factory =
                DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance();
        return factory.getIoServiceProvider();
    }

    public static File getKeyFile() throws Exception {
        String key="Licensed to the Apache Software Foundation (ASF) under one or more\n" +
                "contributor license agreements.  See the NOTICE file distributed with\n" +
                "this work for additional information regarding copyright ownership.\n" +
                "The ASF licenses this file to You under the Apache License, Version 2.0\n" +
                "(the \"License\"); you may not use this file except in compliance with\n" +
                "the License.  You may obtain a copy of the License at\n" +
                "\n" +
                "   http://www.apache.org/licenses/LICENSE-2.0\n" +
                "\n" +
                "Unless required by applicable law or agreed to in writing, software\n" +
                "distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
                "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
                "See the License for the specific language governing permissions and\n" +
                "limitations under the License.\n" +
                "\n" +
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQDdfIWeSV4o68dRrKSzFd/Bk51E65UTmmSrmW0O1ohtzi6HzsDP\n" +
                "jXgCtlTt3FqTcfFfI92IlTr4JWqC9UK1QT1ZTeng0MkPQmv68hDANHbt5CpETZHj\n" +
                "W5q4OOgWhVvj5IyOC2NZHtKlJBkdsMAa15ouOOJLzBvAvbqOR/yUROsEiQIDAQAB\n" +
                "AoGBANG3JDW6NoP8rF/zXoeLgLCj+tfVUPSczhGFVrQkAk4mWfyRkhN0WlwHFOec\n" +
                "K89MpkV1ij/XPVzU4MNbQ2yod1KiDylzvweYv+EaEhASCmYNs6LS03punml42SL9\n" +
                "97tOmWfVJXxlQoLiY6jHPU97vTc65k8gL+gmmrpchsW0aqmZAkEA/c8zfmKvY37T\n" +
                "cxcLLwzwsqqH7g2KZGTf9aRmx2ebdW+QKviJJhbdluDgl1TNNFj5vCLznFDRHiqJ\n" +
                "wq0wkZ39cwJBAN9l5v3kdXj21UrurNPdlV0n2GZBt2vblooQC37XHF97r2zM7Ou+\n" +
                "Lg6MyfJClyguhWL9dxnGbf3btQ0l3KDstxMCQCRaiEqjAfIjWVATzeNIXDWLHXso\n" +
                "b1kf5cA+cwY+vdKdTy4IeUR+Y/DXdvPWDqpf0C11aCVMohdLCn5a5ikFUycCQDhV\n" +
                "K/BuAallJNfmY7JxN87r00fF3ojWMJnT/fIYMFFrkQrwifXQWTDWE76BSDibsosJ\n" +
                "u1TGksnm8zrDh2UVC/0CQFrHTiSl/3DHvWAbOJawGKg46cnlDcAhSyV8Frs8/dlP\n" +
                "7YGG3eqkw++lsghqmFO6mRUTKsBmiiB2wgLGhL5pyYY=\n" +
                "-----END RSA PRIVATE KEY-----";
        File file = File.createTempFile("kserver", ".keystore");
        file.createNewFile();
        FileWriter fw=new FileWriter(file);
        fw.write(key);
        fw.flush();
        fw.close();
//        System.out.println("cccc----"+App.class.getProtectionDomain().getCodeSource().getLocation().getPath());
//        System.out.println("bbbb----"+file.getPath());
//        String abc="jar:file:"+App.class.getProtectionDomain().getCodeSource()
//                .getLocation().getPath()+"!/kserver.keystore";
//        System.out.println("dddd----"+abc);
//        System.out.println("aaaa----"+App.class.getResource(abc).toString());
//
//        InputStream ins = App.class.getResource(abc).openStream();
//
//        OutputStream os = new FileOutputStream(file);
//        int bytesRead = 0;
//        byte[] buffer = new byte[8192];
//        while ((bytesRead = ins.read(buffer, 0, 8192)) != -1) {
//            os.write(buffer, 0, bytesRead);
//        }
//        os.close();
//        ins.close();
        return file;

    }
}
