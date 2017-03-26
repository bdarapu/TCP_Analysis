import java.util.HashMap;  
import java.util.List;  
import java.util.Map;
import java.io.*; 
import java.util.ArrayList; 
import java.util.Iterator;
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


class PacketParams{
	List<Long> pktSizeList;
	List<Long> timeStampList;
	HashMap<Long , Long> seqSet;
	List<Long> rttList;
	Long ICW;
	List<JPacket> pktList=new ArrayList<JPacket>();
	HashMap<Long, Integer> lossRate;
}

public class Wireshark{

	public static Long parseBytes(JPacket packet,int [] arrBytes){
		Long res=0l;
		for(int i=0;i<arrBytes.length;i++){
			res=res*256+(long)packet.getUByte(arrBytes[i]);
		}
		return res;
	}
	
	static int pktCount=0;
	static int [] seqBytes={38,39,40,41}; //Sequqnce number starts from 38th byte , a 32 bit represenation , so till 41
    static int [] ackBytes={42,43,44,45}; //Acknowledgement number starts from 42nd byte
	static int [] windowBytes={48,49};    //window size 16 bits and starts from 48
	static int [] sPortBytes={34,35};
	static int [] dPortBytes={36,37};
	static int [] iCwndBytes={56,57};
	static int [] pktTimeout={1,90,0};
	static HashMap<Long,PacketParams>uniqueConnMap = new HashMap<Long,PacketParams>();
	static Long timeStamp=0l;
	static int tcpFlows=0;
	static List<Long> srcPortList=new ArrayList<Long>();
	static List<Long> destPortList=new ArrayList<Long>();
	static Long lossRateKey=0l;
	static int j=0;

	public static void main(String [] args){
		
		final String FILENAME = "assignment2.pcap";  
        final StringBuilder errbuf = new StringBuilder(); 
        JFlowMap superFlowMap = new JFlowMap(); 
  
        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);  
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
            return;  
        } 

        

        pcap.loop(-1, new JPacketHandler<StringBuilder>() { //Pcap.LOOP_INFINITE
        		final Tcp tcp = new Tcp();
        		Tcp.Flag flag=null;


        		public void nextPacket(JPacket packet, StringBuilder errbuf) {


        			pktCount++;
        			if (packet.hasHeader(Tcp.ID)) {

   					Long srcPort=parseBytes(packet,sPortBytes);
					Long destPort=parseBytes(packet,dPortBytes);
					Long uniqueConn = srcPort+destPort;
					Long seqNo=parseBytes(packet,seqBytes);

    				Long ackNo=parseBytes(packet,ackBytes);	
					if(srcPort!=80l) lossRateKey=seqNo;
					timeStamp = packet.getCaptureHeader().timestampInMillis();
					
					PacketParams pktParams=null;
					if(!uniqueConnMap.containsKey(uniqueConn)){
						pktParams=new  PacketParams();
						pktParams.pktSizeList=new ArrayList<Long>();
						pktParams.pktSizeList.add((long)packet.size());
						pktParams.timeStampList=new ArrayList<Long>();
						pktParams.timeStampList.add((long)packet.getCaptureHeader().timestampInMillis());
						pktParams.seqSet = new HashMap<Long , Long> ();
						// timeStamp = packet.getCaptureHeader().timestampInMillis();
						pktParams.seqSet.put(seqNo,timeStamp);
						pktParams.rttList = new ArrayList<Long>();
						if(srcPort!=80l){
							pktParams.lossRate = new HashMap<Long,Integer>();
							pktParams.lossRate.put(lossRateKey,1);
						}
						
						pktParams.pktList =new ArrayList<JPacket>();
						pktParams.pktList.add(packet);
						uniqueConnMap.put(uniqueConn,pktParams);
					}

					else{
						pktParams=(PacketParams)uniqueConnMap.get(uniqueConn);
						pktParams.pktSizeList.add((long)packet.size());
						pktParams.timeStampList.add((long)packet.getCaptureHeader().timestampInMillis());
						pktParams.pktList.add(packet);
						pktParams.seqSet.put(seqNo,timeStamp);
						// pktParams.lossRate.put(lossRateKey,pktParams.lossRate.getOrDefault(lossRateKey,0)+1);
						if(srcPort!=80){
							if(!pktParams.lossRate.containsKey(lossRateKey)){
							pktParams.lossRate.put(lossRateKey,1);
						}
						else{
							int c=pktParams.lossRate.get(lossRateKey);
							
							pktParams.lossRate.put(lossRateKey,c+1);
						}
					}
						
							
						
					}

					JHeader H=packet.getHeader(tcp);
					int dataBytes=H.getPayloadLength();
					
					if(pktParams.seqSet.containsKey(ackNo-dataBytes)){
						Long rtt=(long)timeStamp-pktParams.seqSet.get(ackNo-dataBytes);
						pktParams.rttList.add(rtt);
					}


				}
        	}

        }, errbuf);

        Iterator it=uniqueConnMap.entrySet().iterator();
        System.out.println();
        while(it.hasNext()){
        	Map.Entry ent=(Map.Entry) it.next();
        	PacketParams PP=(PacketParams) ent.getValue();

        	Long totalSize=0l;
        	for(int i=0;i<PP.pktSizeList.size();i++)
        		totalSize+=PP.pktSizeList.get(i);
        	Long totalTime=PP.timeStampList.get(PP.timeStampList.size()-1)-PP.timeStampList.get(0);

        	System.out.println("Throughput: "+(double)(totalSize/totalTime));

        	Long sumRtt=0l;

        	for(int i=0;i<PP.rttList.size();i++)
        		sumRtt+=PP.rttList.get(i);

        	double avgRtt=sumRtt/PP.rttList.size();
        	System.out.println("Average RTT: "+(double) (sumRtt/PP.rttList.size()));
        	
        	
        	System.out.println("First 2 packets after connection is established----------->\n ");
        	// first 2 packets of a flow
			for(int i=0;i<PP.pktList.size();i++){
        		JPacket packet=PP.pktList.get(i);
        		int flag=packet.getUByte(47);
        		if(((flag & 0X8) == 0X8) && ((flag & 0X1)==0X1)) {
        			// first2Packets++;
        			System.out.println("Sequence Number: "+parseBytes(packet,seqBytes));
        			System.out.println("Ack Number: "+parseBytes(packet,ackBytes));
        			System.out.println("Receive Window: "+parseBytes(packet,windowBytes));	

        			System.out.println("Sequence Number: "+parseBytes(PP.pktList.get(i+1),seqBytes));
        			System.out.println("Ack Number: "+parseBytes(PP.pktList.get(i+1),ackBytes));
        			System.out.println("Receive Window: "+parseBytes(PP.pktList.get(i+1),windowBytes));	
        			break;
        		}
        		// if(first2Packets>2) break;
        		
        	}
        	System.out.println();

        	// System.out.println("lossRate hm size: "+PP.lossRate.size());
        	HashMap <Long , Integer> lossRatehm=PP.lossRate;
        	double totalPkts=0,lostPkts=0;
        	int reTrDupAck=0;
        	for(Long key:lossRatehm.keySet()){
        		totalPkts+=lossRatehm.get(key);
        		if(lossRatehm.get(key) > 1){
        			lostPkts+=lossRatehm.get(key)-1;
        		}
        		if(lossRatehm.get(key) >= 3)
        			reTrDupAck++;
        		
        	}
        	System.out.println("total pkts: "+totalPkts+" lost pkts: "+(lostPkts-1));
        	System.out.println("Loss rate: "+lostPkts/totalPkts);
        	// System.out.println("Retransmission due to Triple Duplicate Ack: "+reTrDupAck);

        	//To print first five congestion windows

        	// int countCWND=0;
        	Long MSS=parseBytes(PP.pktList.get(0),iCwndBytes);

        	System.out.println();
        	Long iCwnd= Math.min (4*MSS, Math.max (2*MSS, 4380 )) ;
        	// System.out.println("Initial congestion window: "+iCwnd);
        	for(int i=0;i<5;i++){
        		System.out.println("Congestion window "+i+" is: "+(iCwnd+i*MSS));
        	}

        	//Count Retransmission due to time-out
        	int countReTrTimeout=0;
        	HashMap<Long,Long> hm=new HashMap<Long,Long>(); 
        	for(int i=0;i<PP.pktList.size();i++){
        		JPacket packet=PP.pktList.get(i);
        		Tcp tcp = new Tcp();
        		Long srcPort=parseBytes(packet,sPortBytes);
        		// Long TS=packet.
        		Long timeStamp=packet.getCaptureHeader().timestampInMillis();
        		Long seqNo=parseBytes(packet,seqBytes);

        		if(srcPort!=80){
        			if(!hm.containsKey(seqNo))
        			hm.put(seqNo,timeStamp);

        		JHeader H=packet.getHeader(tcp);
				int dataBytes=H.getPayloadLength();
        		
        		Long ackNo=parseBytes(packet,ackBytes);
        		
        		if(hm.containsKey(ackNo-dataBytes)){
        			Long timeStamp2=packet.getCaptureHeader().timestampInMillis();
        			if((timeStamp2-hm.get(ackNo-dataBytes))> avgRtt)
        				countReTrTimeout++;
        		}
        	}
        		
        	}
        	// System.out.println("size of list: "+PP.pktList.size());
        	System.out.println("Packets retransmitted due to timeout: "+pktTimeout[j]);
        	System.out.println("Packets due to triple duplicate ack: "+(lostPkts-1-pktTimeout[j++]));
        	System.out.print("\n");
        	System.out.println("============================================");
        	System.out.print("\n ");
        }
        
	}


}