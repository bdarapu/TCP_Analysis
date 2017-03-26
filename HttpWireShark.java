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


public class HttpWireShark{

	public static Long parseBytes(JPacket packet,int [] arrBytes){
		Long res=0l;
		for(int i=0;i<arrBytes.length;i++){
			res=res*256+(long)packet.getUByte(arrBytes[i]);
		}
		return res;
	}

	static int count=0;
	static HashMap<Long,List<JPacket>> hmConnection=new HashMap();
	static int [] seqBytes={38,39,40,41}; //Sequqnce number starts from 38th byte , a 32 bit represenation , so till 41
    static int [] ackBytes={42,43,44,45}; //Acknowledgement number starts from 42nd byte
    static int [] sPortBytes={34,35};
	static int [] dPortBytes={36,37};
	static Long seqNo=0l;
	static Long ackNo=0l;
	static List<String> reqUrl =new ArrayList<String>();
	static List <String> innerTuple=null;
	static List<List<String>> innerTupleList=null;
	static List<List<List<String>>> tupleList=new ArrayList<>();
	static String url=null;
	static List<Long> srcP=new ArrayList();
	static List<Long> destP=new ArrayList();
	static List<JPacket> pktList=null;
	static final Long serverPort=8092l;
	static List<String> urlList=new ArrayList();
	static Long uniqueConn=0l;
	// static int count=0;

	public static void main (String [] args){
		final String FILENAME="http_8092.pcap";
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

					
						Long srcPort=parseBytes(packet,sPortBytes);
						Long destPort=parseBytes(packet,dPortBytes);
						if(!srcP.contains(srcPort)) srcP.add(srcPort);
						if(!destP.contains(destPort)) destP.add(destPort);
						uniqueConn=srcPort+destPort;
						if(!hmConnection.containsKey(uniqueConn)){
							pktList=new ArrayList();
							pktList.add(packet);
							hmConnection.put(uniqueConn,pktList);
						}
						else{
							List<JPacket> li=hmConnection.get(uniqueConn);
							li.add(packet);
							hmConnection.put(uniqueConn,li);
						}
						
					
					
						
				}
			}

		},errbuf);
		System.out.println("Number of Connections: "+hmConnection.size());
		
		for(Long key:hmConnection.keySet()){
			
			List<JPacket> connPktList = hmConnection.get(key);
			
			Long clientPort=key-serverPort;
			Http http=new Http();
			int httpcount=0,cou=0;
			boolean flag=false;
			url=null;
			
			for(int i=0;i<connPktList.size();i++){
				
				JPacket packet=connPktList.get(i);

				if(packet.hasHeader(Tcp.ID)){
					
					Long srcPort=parseBytes(packet,sPortBytes);
					Long destPort=parseBytes(packet,dPortBytes);
					Long seqNo=parseBytes(packet,seqBytes);
					Long ackNo=parseBytes(packet,ackBytes);
					if(packet.hasHeader(http)){
						
						if(http.fieldValue(Request.RequestUrl)!=null){
							url=http.fieldValue(Request.RequestUrl);
							if(!urlList.contains(url))
								urlList.add(url);
							 
							innerTupleList=new ArrayList();

							
						}
						
						
					}
					if(url!=null){
						innerTuple=new ArrayList();
						
						if(srcPort==8092l){
							
							innerTuple.add(String.valueOf(srcPort));
							innerTuple.add(String.valueOf(destPort));
							innerTuple.add(String.valueOf(seqNo));
							innerTuple.add(String.valueOf(ackNo));
							innerTupleList.add(innerTuple);
							
						}
					}
				}
			}
			tupleList.add(innerTupleList);
			
			System.out.println(url);
			// System.out.println(innerTupleList.size());
			System.out.println(Arrays.toString(innerTupleList.toArray()));
		}
		
		
	}
}