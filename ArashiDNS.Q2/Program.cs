using ARSoft.Tools.Net.Dns;
using McMaster.Extensions.CommandLineUtils;
using System.Collections.Generic;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

[assembly: RequiresPreviewFeatures]
namespace ArashiDNS.Q2
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Any, 853);
        public static IPAddress UpEndPoint = IPAddress.Parse("8.8.8.8");
        public static int Timeout = 1000;
        public static X509Certificate2Collection Certificate2Collection = new();

        private static readonly List<SslApplicationProtocol> QuicApplicationProtocols =
        [
            new SslApplicationProtocol("doq") //new SslApplicationProtocol("dq"),
            //new SslApplicationProtocol("dq-i02"), new SslApplicationProtocol("dq-i00")
        ];

        static async Task Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.Q2",
                Description = "ArashiDNS.Q2 - DNS over QUIC Server" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MIT License"
            };
            cmd.HelpOption("-?|-h|--help");

            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var upArgument = cmd.Argument("target",
                isZh ? "目标上游 DNS 端点" : "Target upstream DNS service endpoint");
            var ipOption = cmd.Option("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var pemOption = cmd.Option("-p|--pem <Path>",
                isZh ? "PEM 证书文件路径" : "PEM certificate file path", CommandOptionType.SingleValue);
            var keyOption = cmd.Option("-k|--key <Path>",
                isZh ? "私钥文件路径" : "Private key file path", CommandOptionType.SingleValue);
            var crtsOption = cmd.Option("-c|--crts <URL>",
                isZh ? "证书链，CA 证书 URL" : "Certificate chain, CA certificate URL", CommandOptionType.MultipleValue);
            var wOption = cmd.Option<int>("-w <timeout>",
                isZh ? "等待回复的超时时间(毫秒)。" : "Timeout time to wait for reply", CommandOptionType.SingleValue);

            cmd.OnExecuteAsync(async c =>
            {
                foreach (var item in crtsOption.Values)
                {
                    try
                    {
                        Certificate2Collection.Add(X509Certificate2.CreateFromPem(new HttpClient()
                            .GetStringAsync(item ?? string.Empty, c).Result));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }

                if (upArgument.HasValue) UpEndPoint = IPEndPoint.Parse(upArgument.Value!).Address;
                if (ipOption.HasValue()) ListenerEndPoint = IPEndPoint.Parse(ipOption.Value()!);
                if (wOption.HasValue()) Timeout = int.Parse(wOption.Value()!);

                var pem = File.ReadAllText(pemOption.Value() ?? "crt.crt");
                var key = File.ReadAllText(keyOption.Value() ?? "key.key");
                var cert = X509Certificate2.CreateFromPem(pem, key);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    cert = new X509Certificate2(cert.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);

                var sslOptions = new SslServerAuthenticationOptions()
                {
                    ApplicationProtocols = QuicApplicationProtocols,
                    ServerCertificateContext = SslStreamCertificateContext.Create(cert, Certificate2Collection),
                    ClientCertificateRequired = false,
                };
                var listenerOptions = new QuicListenerOptions()
                {
                    ListenEndPoint = ListenerEndPoint,
                    ListenBacklog = 100,
                    ApplicationProtocols = QuicApplicationProtocols,
                    ConnectionOptionsCallback = delegate
                    {
                        var serverConnectionOptions = new QuicServerConnectionOptions()
                        {
                            DefaultCloseErrorCode = 0,
                            DefaultStreamErrorCode = 5,
                            MaxInboundUnidirectionalStreams = 0,
                            MaxInboundBidirectionalStreams = 100,
                            IdleTimeout = TimeSpan.FromMilliseconds(1000),
                            ServerAuthenticationOptions = sslOptions
                        };
                        return ValueTask.FromResult(serverConnectionOptions);
                    }
                };

                var listener = await QuicListener.ListenAsync(listenerOptions, c);
                for (var i = 0; i < 4; i++) await Task.Factory.StartNew(() => AcceptQuicConnection(listener), c);
                Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");

                if (!Console.IsInputRedirected && Console.KeyAvailable)
                {
                    while (true)
                        if (Console.ReadKey().KeyChar == 'q')
                            Environment.Exit(0);
                }

                EventWaitHandle wait = new AutoResetEvent(false);
                while (true) wait.WaitOne();
            });

            cmd.Execute(args);
        }

        static async Task AcceptQuicConnection(QuicListener quicListener)
        {
            try
            {
                while (true)
                {
                    try
                    {
                        var connection = await quicListener.AcceptConnectionAsync();
                        _ = Task.Run(async () =>
                        {
                            while (true)
                            {
                                var stream = await connection.AcceptInboundStreamAsync();
                                _ = HandleQuicStreamRequest(stream);
                            }
                        });
                    }
                    catch (QuicException ex)
                    {
                        switch (ex.QuicError)
                        {
                            case QuicError.ConnectionIdle:
                            case QuicError.InternalError:
                            case QuicError.ConnectionAborted:
                            case QuicError.ConnectionTimeout:
                                break;

                            default:
                                Console.WriteLine(ex);
                                break;
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        // ignore
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static async Task HandleQuicStreamRequest(QuicStream stream)
        {
            var qBytes = new byte[512];
            byte additional = 0;
            try
            {
                var len = await stream.ReadAsync(qBytes);
                if (len == 0) return;

                var qListBytes = qBytes.Take(len).ToList();
                if (qListBytes[1] != 0)
                {
                    additional = qListBytes[1];
                    qListBytes.RemoveRange(0, 2);
                }

                qBytes = qListBytes.ToArray();
                var query = DnsMessage.Parse(qBytes);

                if (query.IsEDnsEnabled)
                    query.EDnsOptions?.Options.RemoveAll(x => x.Type != EDnsOptionType.ClientSubnet);

                var response = await new DnsClient(UpEndPoint, Timeout).SendMessageAsync(query);

                if (response != null)
                {
                    response.IsRecursionAllowed = true;
                    response.IsRecursionDesired = true;
                    response.IsTruncated = false;
                    response.IsQuery = false;
                    response.IsEDnsEnabled = false;
                    response.EDnsOptions?.Options.Clear();
                    response.AdditionalRecords.Clear();
                    response.TransactionID = query.TransactionID;
                }
                else
                {
                    response = query.CreateResponseInstance();
                    response.ReturnCode = ReturnCode.ServerFailure;
                }

                var bytes = response.Encode().ToArraySegment(false).ToList();
                if (additional != 0) bytes.InsertRange(0, GetPrefix(bytes.ToArray()));
                await stream.WriteAsync(bytes.ToArray());
            }
            catch (IOException)
            {
                //ignore
            }
            catch (Exception ex)
            {
                Console.WriteLine(Convert.ToBase64String(qBytes));
                Console.WriteLine(ex);
            }
            finally
            {
                //quicStream.Close();
                await stream.DisposeAsync();
            }
        }

        public static byte[] GetPrefix(byte[] data)
        {
            return [(byte) ((data.Length + 2) >> 8), (byte) (data.Length + 2)];
        }
    }
}
