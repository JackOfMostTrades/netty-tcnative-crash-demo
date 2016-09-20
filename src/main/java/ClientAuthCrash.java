import io.grpc.*;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.*;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Demonstrate the boringssl SIGABRT crash that occurs during TLS handshake when
 * the client passes a certificate chain.
 */
public class ClientAuthCrash {
    private static String X509_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIB9jCCAV+gAwIBAgIJAO9fzyjyV5BhMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n" +
            "BAMMCWxvY2FsaG9zdDAeFw0xNjA5MjAxOTI0MTVaFw00NDEwMDMxOTI0MTVaMBQx\n" +
            "EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n" +
            "1Kp6DmwRiI+TNs3rZ3WvceDYQ4VTxZQk9jgHVKhHTeA0LptOaazbm9g+aOPiCc6V\n" +
            "5ysu8T8YRLWjej3by2/1zPBO1k25dQRK8dHr0Grmo20FW7+ES+YxohOfmi7bjOVm\n" +
            "NrI3NoVZjf3fQjAlrtKCmaxRPgYEwOT0ucGfJiEyV9cCAwEAAaNQME4wHQYDVR0O\n" +
            "BBYEFIba521hTU1P+1QHcIqAOdAEgd1QMB8GA1UdIwQYMBaAFIba521hTU1P+1QH\n" +
            "cIqAOdAEgd1QMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAHG5hBy0b\n" +
            "ysXKJqWQ/3bNId3VCzD9U557oxEYYAuPG0TqyvjvZ3wNQto079Na7lYkTt2kTIYN\n" +
            "/HPW2eflDyXAwXmdNM1Gre213NECY9VxDBTCYJ1R4f2Ogv9iehwzZ4aJGxEDay69\n" +
            "wrGrxKIrKL4OMl/E+R4mi+yZ0i6bfQuli5s=\n" +
            "-----END CERTIFICATE-----\n";

    private static String PRIVATE_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANSqeg5sEYiPkzbN\n" +
            "62d1r3Hg2EOFU8WUJPY4B1SoR03gNC6bTmms25vYPmjj4gnOlecrLvE/GES1o3o9\n" +
            "28tv9czwTtZNuXUESvHR69Bq5qNtBVu/hEvmMaITn5ou24zlZjayNzaFWY3930Iw\n" +
            "Ja7SgpmsUT4GBMDk9LnBnyYhMlfXAgMBAAECgYAeyc+B5wNi0eZuOMGr6M3Nns+w\n" +
            "dsz5/cicHOBy0SoBjEQBu1pO0ke4+EWQye0fnlj1brsNEiVhTSqtt+bqPPtIvKtZ\n" +
            "U4Z2M5euUQL390LnVM+jlaRyKUFVYzFnWfNgciT6SLsrbGRz9EhMH2jM6gi8O/cI\n" +
            "n8Do9fgHon9dILOPAQJBAO/3xc0/sWP94Cv25ogsvOLRgXY2NqY/PDfWat31MFt4\n" +
            "pKh9aad7SrqR7oRXIEuJ+16drM0O+KveJEjFnHgcq18CQQDi38CqycxrsL2pzq53\n" +
            "XtlhbzOBpDaNjySMmdg8wIXVVGmFC7Y2zWq+cEirrI0n2BJOC4LLDNvlT6IjnYqF\n" +
            "qp6JAkBQfB0Wyz8XF4aBmG0XzVGJDdXLLUHFHr52x+7OBTez5lHrxSyTpPGag+mo\n" +
            "74QAcgYiZOYZXOUg1//5fHYPfyYnAkANKyenwibXaV7Y6GJAE4VSnn3C3KE9/j0E\n" +
            "3Dks7Y/XHhsx2cgtziaP/zx4mn9m/KezV/+zgX+SA9lJb++GaqzhAkEAoNfjQ4jd\n" +
            "3fsY99ZVoC5YFASSKf+DBqcVOkiUtF1pRwBzLDgKW14+nM/v7X+HJzkfnNTj4cW/\n" +
            "nUq37uAS7oJc4g==\n" +
            "-----END PRIVATE KEY-----\n";

    private static String CLIENT_X509_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBlzCCAQACAQEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0\n" +
            "MB4XDTE2MDkyMDE5NTIyMFoXDTE3MDkyMDE5NTIyMFowFDESMBAGA1UEAwwJdGxz\n" +
            "Y2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB19iXOYtyPp6cMJiG\n" +
            "9C9QNw/ro6SWpv9H0wPcPBhWRrPBJvXppVWxMMxYuJFSKC8cGRqpK+k0h9omn2l+\n" +
            "c1ReKFEMi0csZRZMGjkUYv0/ol6tlz0CFvQOU5lRxkh1JWI/P1/b36zJCTvyNEV4\n" +
            "upjAV1eAu27twS8hBrPK2+pIqwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAMa35kuy\n" +
            "WzuHLg7iwnDVX4ZT/4iTJg1fZDms2dTqFWH+RYlxsytePUkY3ksGHl+VJgoDBK3X\n" +
            "G6/dqNa5BQDyFF0/dDQ2XYTrj5Yd0MsLA00AkFdSow5RyhWXJXzVHgKE48ZFW5Bt\n" +
            "NW9uXaerRzFR1mG2+0AghxCNMhuWxIblW7L0\n" +
            "-----END CERTIFICATE-----\n";

    private static String CLIENT_PRIVATE_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMHX2Jc5i3I+npww\n" +
            "mIb0L1A3D+ujpJam/0fTA9w8GFZGs8Em9emlVbEwzFi4kVIoLxwZGqkr6TSH2iaf\n" +
            "aX5zVF4oUQyLRyxlFkwaORRi/T+iXq2XPQIW9A5TmVHGSHUlYj8/X9vfrMkJO/I0\n" +
            "RXi6mMBXV4C7bu3BLyEGs8rb6kirAgMBAAECgYBKPKrzh5NTJo5CDQ5tKNlx5BSR\n" +
            "zzM6iyxbSoJA9zbu29b90zj8yVgfKywnkk/9Yexg23Btd6axepHeltClH/AgD1GL\n" +
            "QE9bpeBMm8r+/9v/XR/mn5GjTxspj/q29mqOdg8CrKb8M6r1gtj70r8nI8aqmDwV\n" +
            "b6/ZTpsei+tN635Y2QJBAP1FHtIK2Z4t2Ro7oNaiv3s3TsYDlj14ladG+DKi2tW+\n" +
            "9PW7AO8rLAx2LWmrilXDFc7UG6hvhmUVkp7wXRCK0dcCQQDD7r3g8lswdEAVI0tF\n" +
            "fzJO61vDR12Kxv4flar9GwWdak7EzCp//iYNPWc+S7ONlYRbbI+uKVL/KBlvkU9E\n" +
            "4M1NAkEAy0ZGzl5W+1XhAeUJ2jsVZFenqdYHJ584veGAI2QCL7vr763/ufX0jKvt\n" +
            "FvrPNLY3MqGa8T1RqJ//5gEVMMm6UQJAKpBJpX1gu/T1GuJw7qcEKcrNQ23Ub1pt\n" +
            "SDU+UP+2x4yZkfz8WpO+dm/ZZtoRJnfNqgK6b85AXne6ltcNTlw7nQJBAKnFel18\n" +
            "Tg2ea308CyM+SJQxpfmU+1yeO2OYHNmimjWFhQPuxIDP9JUzpW39DdCDdTcd++HK\n" +
            "xJ5gsU/5OLk6ySo=\n" +
            "-----END PRIVATE KEY-----\n";

    private static String CLIENT_X509_CERT_CHAIN_PEM = CLIENT_X509_CERT_PEM + X509_CERT_PEM;

    public static class IntMarshaller implements MethodDescriptor.Marshaller<Integer> {
        public InputStream stream(Integer value) {
            return new ByteArrayInputStream(value.toString().getBytes());
        }
        public Integer parse(InputStream stream) {
            java.util.Scanner s = new java.util.Scanner(stream).useDelimiter("\\A");
            return Integer.parseInt(s.hasNext() ? s.next() : "");
        }
    }
    private static IntMarshaller INT_MARSHALLER = new IntMarshaller();

    public static class DummyService implements BindableService {
        public static MethodDescriptor<Integer, Integer> INVOKE_METHOD =
            MethodDescriptor.create(MethodDescriptor.MethodType.UNARY,
                    MethodDescriptor.generateFullMethodName("DummyService", "Invoke"),
            INT_MARSHALLER,
            INT_MARSHALLER);

        public ServerServiceDefinition bindService() {
            return ServerServiceDefinition.builder("DummyService")
                    .addMethod(INVOKE_METHOD,
                            ServerCalls.asyncUnaryCall(new ServerCalls.UnaryMethod<Integer, Integer>() {
                                @Override
                                public void invoke(Integer request, StreamObserver<Integer> responseObserver) {
                                    System.out.println("Request: " + request);
                                    responseObserver.onNext(42);
                                    responseObserver.onCompleted();
                                }
                            }))
                    .build();
        }
    }

    public static void main(String[] argv) throws Exception {
        NettyServerBuilder builder = NettyServerBuilder.forAddress(new InetSocketAddress("localhost", 4999));

        SslContextBuilder serverSslContextBuilder = GrpcSslContexts.configure(
                SslContextBuilder.forServer(
                    new ByteArrayInputStream(X509_CERT_PEM.getBytes(StandardCharsets.UTF_8)),
                    new ByteArrayInputStream(PRIVATE_KEY_PEM.getBytes(StandardCharsets.UTF_8)))
                .trustManager(new ByteArrayInputStream(X509_CERT_PEM.getBytes(StandardCharsets.UTF_8)))
                .clientAuth(ClientAuth.REQUIRE)
        );

        builder.sslContext(serverSslContextBuilder.build());

        DummyService dummyService = new DummyService();

        builder.addService(dummyService.bindService());

        Server grpcServer = builder.build();
        grpcServer.start();

        ManagedChannel clientAuthChannel = NettyChannelBuilder.forAddress("localhost", 4999)
                .sslContext(GrpcSslContexts.configure(
                        SslContextBuilder.forClient()
                                .keyManager(
                                        // Change this to CLIENT_X509_CERT_PEM and the crash will not occur.
                                        new ByteArrayInputStream(CLIENT_X509_CERT_CHAIN_PEM.getBytes(StandardCharsets.UTF_8)),
                                        new ByteArrayInputStream(CLIENT_PRIVATE_KEY_PEM.getBytes(StandardCharsets.UTF_8)))
                                .trustManager(new ByteArrayInputStream(X509_CERT_PEM.getBytes(StandardCharsets.UTF_8)))
                ).build()).build();

        Integer response = ClientCalls.blockingUnaryCall(
                clientAuthChannel,
                DummyService.INVOKE_METHOD,
                CallOptions.DEFAULT, 37);
        System.out.println("Response: " + response);

        grpcServer.shutdown();
        grpcServer.awaitTermination();
    }
}
