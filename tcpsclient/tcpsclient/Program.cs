using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace evinci
{
    public class SslTcpClient
    {

        private static Hashtable certificateErrors = new Hashtable();

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;


            //xxxmor, here for now
            return true;


            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors || certificate.Subject == certificate.Issuer)
            {

                // If THIS is the cause of of the error then allow the certificate, a static 0 as the index is safe given chain.ChainStatus.Length == 1.



                if (chain.ChainStatus[0].Status == X509ChainStatusFlags.UntrustedRoot || chain.ChainStatus[0].Status == X509ChainStatusFlags.NotValidForUsage)
                {



                    // Self-signed certificates with an untrusted root are valid.



                    return true;

                }

            }

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            //  allow this client to communicate with unauthenticated servers.
            return false;
        }

     
        public static void RunClient(string machineName, string serverName,int port, SslProtocols sslprotocol)
        {
            
           // ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(ServerCertCallback);


            //ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            TcpClient client;
            SslStream sslStream;
            try
            {
                // Create a TCP/IP client socket.
                // machineName is the host running the server application.
                client = new TcpClient(machineName, port);
                Console.WriteLine("Client connected.");
                // Create an SSL stream that will close the client's stream.
                sslStream = new SslStream(
                    client.GetStream(),
                    false,
                    new RemoteCertificateValidationCallback(ValidateServerCertificate),
                    null
                    );
                sslStream.ReadTimeout = 30000;
                // The server name must match the name on the server certificate.
               
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
             
                return;
            }
            try
            {
                //X509Certificate2 test = new X509Certificate2();

                sslStream.AuthenticateAsClient(serverName, null, sslprotocol, false);
                Console.WriteLine("cipher algorithm={0}", sslStream.CipherAlgorithm);
                Console.WriteLine("hash algorithm={0}", sslStream.HashAlgorithm);
                Console.WriteLine("keyExchange algorithm={0}", sslStream.KeyExchangeAlgorithm);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }

            Console.WriteLine("Authenticated.");
            // Encode a test message into a byte array.
            // Signal the end of the message using the "<EOF>".
            string msg = "SENT<EOF>";
            //msg = "SENT";
            msg = @"~-{LI/cstd/c.php?n=&c=SB&s=LDo3SV04SL04FC17&u=slo3&p=qJR29Zc2}E9";
           
            byte[] messsage = Encoding.UTF8.GetBytes(msg);
            // Send hello message to the server. 
            sslStream.Write(messsage);
            sslStream.Flush();
          
            // Read message from the server.
            for (int i = 0; i < 10; i++)
            {
                string serverMessage = ReadMessage(sslStream);
               if (!String.IsNullOrEmpty(serverMessage)) Console.WriteLine("Server says: {0}", serverMessage);
            }
            // Close the client connection.
            client.Close();
            Console.WriteLine("Client closed.");
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            for (int i = 0; i < 2048; i++)
            {
                buffer[i] = 0;
            }
            StringBuilder messageData = new StringBuilder();
            messageData.Clear();
            int bytes = -1;
            do
            {
                try
                {
                    bytes = sslStream.Read(buffer, 0, buffer.Length);
                }
                catch (Exception ex)
                {
                    break;
                }
                
                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                if (bytes > 0)
                {
                    Decoder decoder = Encoding.UTF8.GetDecoder();
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];

                    decoder.GetChars(buffer, 0, bytes, chars, 0);
                    for (int i = 0; i < bytes; i++)
                    {
                        Console.Write(" 0x{0:X2}", buffer[i]);
                    }
                    messageData.Append(chars);
                }

                //Console.WriteLine(messageData);
                // Check for EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
        private static void DisplayUsage()
        {
            Console.WriteLine("To start the client specify:");
            Console.WriteLine("clientSync machineName [serverName]");
            Environment.Exit(1);
        }
        public static int Main(string[] args)
        {
            TCPCLIENTCONFIG tcpconfig = new TCPCLIENTCONFIG();
            XmlSerializer xmls = new XmlSerializer(typeof(TCPCLIENTCONFIG));
            if (System.IO.File.Exists("tcp.client.cfg"))
            {
                try
                {
                    using (FileStream file = File.OpenRead("tcp.client.cfg"))
                    {
                        tcpconfig = (TCPCLIENTCONFIG)xmls.Deserialize(file);
                    }
                }
                catch
                {
                    tcpconfig.SetDefault();
                }
            }
            else
            {
                tcpconfig.SetDefault();


                using (FileStream file = File.OpenWrite("tcp.client.cfg"))
                {
                    xmls.Serialize(file, tcpconfig);
                }
            }

            string serverCertificateName = null;
            string machineName = null;
            // User can specify the machine name and server name.
            // Server name must match the name on the server's certificate. 
            machineName = tcpconfig.serverAddr; //"192.168.3.106";// "76.10.128.38";// "192.168.1.97"; //"192.168.3.104";

            serverCertificateName = tcpconfig.serverCertificateName;// "Test Labs (CA)";

            SslTcpClient.RunClient(machineName, serverCertificateName, tcpconfig.serverPort,tcpconfig.protocol);

            Console.ReadKey();
            return 0;
        }
    }
}
