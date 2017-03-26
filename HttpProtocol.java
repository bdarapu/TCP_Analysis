import java.util.HashMap;  
import java.util.List;  
import java.util.Map;
import java.io.*; 
import java.util.ArrayList; 
import java.util.Iterator;
import java.util.Arrays;

//all packets printed same when tried to jheader to pktlist , so added Jpacket - 
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Http.Response;

public class HttpProtocol{

	static List<String> httpVer=new ArrayList();
	static int [] sPortBytes={34,35};
	static int [] dPortBytes={36,37};
	static List<Long> uniqueConnList=new ArrayList();
	static Long startTime=0l;
	static Long endTime=0l;
	static Boolean flag=false;
	static Long totalSize=0l;
	static Long count=0l;

	public static Long parseBytes(JPacket packet,int [] arrBytes){
		Long res=0l;
		for(int i=0;i<arrBytes.length;i++){
			res=res*256+(long)packet.getUByte(arrBytes[i]);
		}
		return res;
	}

	public static void main (String [] args){
		final String FILENAME=args[0];
		final StringBuilder errbuf=new StringBuilder();
		
		final Pcap pcap=Pcap.openOffline(FILENAME,errbuf);
		if(pcap==null) {
			System.out.println(errbuf);
			return ;
		}

		pcap.loop(-1, new JPacketHandler<StringBuilder>() {

			final Tcp tcp = new Tcp();
			final Http http = new Http();

			public void nextPacket(JPacket packet , StringBuilder errbuf){

				if(packet.hasHeader(Tcp.ID)){
					if(!flag){
						startTime=(long)packet.getCaptureHeader().timestampInMillis();
						flag=true;
					}
					endTime=(long)packet.getCaptureHeader().timestampInMillis();
					totalSize+=packet.size();
					count++;
						
					if(packet.hasHeader(http)){

						String ver=http.fieldValue(Request.RequestVersion);
						if(!httpVer.contains(ver)) httpVer.add(ver);
					}
					Long srcPort=parseBytes(packet,sPortBytes);
					Long destPort=parseBytes(packet,dPortBytes);
					if(!uniqueConnList.contains(srcPort+destPort)) uniqueConnList.add(srcPort+destPort);
				}
			}
		},errbuf);
		for(String ver:httpVer)
			System.out.println(ver);
		System.out.println(uniqueConnList.size());
		System.out.println("Total time: "+(endTime-startTime));
		System.out.println("total number of bytes sent: "+totalSize);
		System.out.println("Number of packets: "+count);
	}
}