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


import java.io.IOException;
import java.nio.file.Paths;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws Exception {
        System.setProperty("org.apache.sshd.common.io.IoServiceFactoryFactory","org.apache.sshd.netty.NettyIoServiceFactoryFactory");
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
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(22);

        //*give host key generator a path, when sshd server restart, the same key will be load and used to authenticate the server
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("kserver.keystore")));

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
}
