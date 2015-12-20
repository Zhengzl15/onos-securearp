/*
 * Copyright 2014-2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.securearp;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onlab.osgi.ServiceDirectory;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv6;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.PipelinerContext;
import org.onosproject.net.driver.DefaultDriverData;
import org.onosproject.net.driver.Driver;
import org.onosproject.net.driver.DriverService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.FlowObjectiveStore;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective.Flag;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Sample reactive forwarding application.
 */
@Component(immediate = true)
@Service
public class SecureArp implements SecureArpService {

	private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DriverService driverService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveStore flowObjectiveStore;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;
    
    //@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
   // protected DhcpService dhcpService;
    
    private ApplicationId appId;
    
    private static final String DRIVER_NAME = "onosfw";
    protected ServiceDirectory serviceDirectory = new DefaultServiceDirectory();
    
    //功能1 基本代理功能
    private Timer replyTimer;
    private static final long REPLY_INTERVAL = 1000L;   
    private SecureArpProcessor processor = new SecureArpProcessor();
    //存储host发来的arp request请求，用作调度。使用concurrenthashmap防止竞争条件,k-v对应targetIp-set(arpRequest)
//    private Map<IpAddress, HashSet<ArpRequestRecord>> arpRequests = new ConcurrentHashMap<IpAddress, HashSet<ArpRequestRecord> >();
    //存储学习到的ip-mac对应值
    private Map<IpAddress, MacAddress> ipMacTable = new ConcurrentHashMap<IpAddress, MacAddress>();
    
    //功能2 监测攻击
    private static final long CHECK_INTERVAL = 5 * 1000L;
    private static final int REQUEST_THRESHOLD = 10;
    private static final int DROP_TIMEOUT = 600;
    private static final int DROP_PRORITY = 65535;
    //统计arp request/reply的频率
    //private Map<ArpRequestRecord, Integer> arpRequestFrequence = new ConcurrentHashMap<ArpRequestRecord, Integer>();
    private Map<ArpRecord, Integer> arpFrequence = new ConcurrentHashMap<ArpRecord, Integer>();    
    private Timer checkTimer;
    
    @Property(name = "ipv6NeighborDiscovery", boolValue = false,
            label = "Enable IPv6 Neighbor Discovery; default is false")
    protected boolean ipv6NeighborDiscovery = false;

    @Activate
    public void activate(ComponentContext context) {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.onosproject.securearp");

        packetService.addProcessor(processor, PacketProcessor.director(1));
        readComponentConfiguration(context);
        requestPackets();
        
       // replyTimer = new Timer();
      //  replyTimer.schedule(new ArpRequestTimerTask(), REPLY_INTERVAL, REPLY_INTERVAL);

        checkTimer = new Timer();
        checkTimer.schedule(new AntiAttackTimerTask(), 3, CHECK_INTERVAL);
        
        log.info("Started with Application ID {}", appId.id());
        
        //initialized ip-mac talbe
        //ipMacTable.put(IpAddress.valueOf("10.0.0.2"), MacAddress.valueOf("11:22:33:44:55:66"));
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        withdrawIntercepts();
        packetService.removeProcessor(processor);
        processor = null;
        replyTimer.cancel();
        checkTimer.cancel();
        
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
        requestPackets();
    }

    /**
     * Request packet in via PacketService.
     */
    private void requestPackets() {
        TrafficSelector.Builder selectorBuilder =
                DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selectorBuilder.build(),
                                     PacketPriority.CONTROL, appId);

        selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV6);
        selectorBuilder.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        selectorBuilder.matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        if (ipv6NeighborDiscovery) {
            // IPv6 Neighbor Solicitation packet.
            packetService.requestPackets(selectorBuilder.build(),
                                         PacketPriority.CONTROL, appId);
        } else {
            packetService.cancelPackets(selectorBuilder.build(),
            							 PacketPriority.CONTROL, appId);
        }

        // IPv6 Neighbor Advertisement packet.
        selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV6);
        selectorBuilder.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        selectorBuilder.matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        if (ipv6NeighborDiscovery) {
            packetService.requestPackets(selectorBuilder.build(),
            							PacketPriority.CONTROL, appId);
        } else {
            packetService.cancelPackets(selectorBuilder.build(),
            							PacketPriority.CONTROL, appId);
        }


    }

    /**
     * Cancel requested packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selectorBuilder =
                DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selectorBuilder.build(), PacketPriority.CONTROL, appId);
        selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV6);						
        selectorBuilder.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        selectorBuilder.matchIcmpv6Type(ICMP6.NEIGHBOR_SOLICITATION);
        packetService.cancelPackets(selectorBuilder.build(), PacketPriority.CONTROL, appId);
        selectorBuilder = DefaultTrafficSelector.builder();
        selectorBuilder.matchEthType(Ethernet.TYPE_IPV6);
        selectorBuilder.matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        selectorBuilder.matchIcmpv6Type(ICMP6.NEIGHBOR_ADVERTISEMENT);
        packetService.cancelPackets(selectorBuilder.build(), PacketPriority.CONTROL, appId);

    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        Boolean flag;

        flag = isPropertyEnabled(properties, "ipv6NeighborDiscovery");
        if (flag == null) {
            log.info("IPv6 Neighbor Discovery is not configured, " +
                             "using current value of {}", ipv6NeighborDiscovery);
        } else {
            ipv6NeighborDiscovery = flag;
            log.info("Configured. IPv6 Neighbor Discovery is {}",
                     ipv6NeighborDiscovery ? "enabled" : "disabled");
        }
    }

    /**
     * Check property name is defined and set to true.
     *
     * @param properties   properties to be looked up
     * @param propertyName the name of the property to look up
     * @return value when the propertyName is defined or return null
     */
    private static Boolean isPropertyEnabled(Dictionary<?, ?> properties,
                                             String propertyName) {
        Boolean value = null;
        try {
            String s = (String) properties.get(propertyName);
            value = isNullOrEmpty(s) ? null : s.trim().equals("true");
        } catch (ClassCastException e) {
            // No propertyName defined.
            value = null;
        }
        return value;
    }
    
    /**
     * 
     */    
    private class ArpRecord {
    	private ARP arp;
    	private DeviceId switchId;
    	private PortNumber inPort;
    	
    	public ArpRecord(ARP arp, DeviceId swId, PortNumber portNum) {
    		this.arp = arp;
    		this.switchId = swId;
    		this.inPort = portNum;
    	}
    	
    	public ARP getArp () {
    		return this.arp;
    	}
    	
    	public void setArp (ARP arp) {
    		this.arp = arp;
    	}
    	
    	public DeviceId getSwitchId () {
    		return this.switchId;
    	}
    	
    	public void setSwitchId (DeviceId swId) {
    		this.switchId = swId;
    	}
    	
    	public PortNumber getInPort () {
    		return this.inPort;
    	}
    	
    	public void setInPort (PortNumber portNum) {
    		this.inPort = portNum;
    	}
    	
    	@Override
    	public int hashCode () {
    		int result = 0;
    		try {
	    		IpAddress sourceIp = IpAddress.valueOf(InetAddress.getByAddress(this.arp.getSenderProtocolAddress()));
	    		result = result + sourceIp.toString().hashCode();
	    		MacAddress sourceMac = MacAddress.valueOf(this.arp.getSenderHardwareAddress());
	    		result = result + sourceMac.toString().hashCode();
	    		IpAddress targetIp = IpAddress.valueOf(InetAddress.getByAddress(this.arp.getTargetProtocolAddress()));
	    		result = result + targetIp.toString().hashCode();
    		} catch (Exception e) {
    			e.printStackTrace();
    		}
    	
    		return result;
    	}
    	
    	@Override
    	public boolean equals (Object obj) {
    		if (this == obj) {
                return true;
            }
            if (!(obj instanceof ArpRecord)) {

                return false;
            }
    		ArpRecord other = (ArpRecord)obj;
    		try {
	    		IpAddress sourceIp = IpAddress.valueOf(InetAddress.getByAddress(this.arp.getSenderProtocolAddress()));
	    		IpAddress otherSourceIp = IpAddress.valueOf(InetAddress.getByAddress(other.arp.getSenderProtocolAddress()));
	    		boolean cmp = sourceIp.toString().equals(otherSourceIp.toString());
	    		if (!cmp) {
	    			return false;
	    		}
	    		MacAddress sourceMac = MacAddress.valueOf(this.arp.getSenderHardwareAddress());
	    		MacAddress otherSourceMac = MacAddress.valueOf(other.arp.getSenderHardwareAddress());
	    		cmp = sourceMac.toString().equals(otherSourceMac.toString());
	    		if (!cmp) {
	    			return false;
	    		}
	    		IpAddress targetIp = IpAddress.valueOf(InetAddress.getByAddress(this.arp.getTargetProtocolAddress()));
	    		IpAddress otherTargetIp = IpAddress.valueOf(InetAddress.getByAddress(other.arp.getTargetProtocolAddress()));
	    		cmp = targetIp.toString().equals(otherTargetIp.toString());
	    		return cmp;
    		} catch (Exception e) {
    			e.printStackTrace();
    			return false;
    		}
    	}
    } 

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class SecureArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {           	
            	//获取arp包
            	ARP arpPkt = (ARP)ethPkt.getPayload();
            	
            	if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
            		try {
            			handleArpRequest(context);
            			arpCount(context);
            		} catch (Exception e) {
            			e.printStackTrace();
            		}
            	} else if (arpPkt.getOpCode() == ARP.OP_REPLY) {
            		try {
//            			handleArpReply(context);
            			arpCount(context);
            		} catch (Exception e) {
            			e.printStackTrace();
            		}
            	} else {
            		log.warn("exception in arp packet");
            		return;
            	}
                //handle the arp packet.
               // proxyArpService.handlePacket(context);
            } else if (ipv6NeighborDiscovery && ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
                if (ipv6Pkt.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Pkt = (ICMP6) ipv6Pkt.getPayload();
                    if (icmp6Pkt.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION ||
                        icmp6Pkt.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                        // handle ICMPv6 solicitations and advertisements
                      //  proxyArpService.handlePacket(context);
                    }
                }
            }

            // FIXME why were we listeni    		System.out.println("Equals");ng to IPv4 frames at all?
            // Do not ARP for multicast packets.  Let mfwd handle them.
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (ethPkt.getDestinationMAC().isMulticast()) {
                    return;
                }
            }
        }               
    }//end SecureArpProcessor
    
    private void handleArpRequest(PacketContext context) throws UnknownHostException {
    	InboundPacket pkt = context.inPacket();
    	Ethernet ethPkt = pkt.parsed(); 
    	
    	ARP arpPkt = (ARP)ethPkt.getPayload();
    	
    	//将arp request包的sourceip和sourcemac学习到ipmactables里。
    	IpAddress sourceIp = IpAddress.valueOf(InetAddress.getByAddress(arpPkt.getSenderProtocolAddress()));
    	System.out.println("request --->  source ip: " + sourceIp.toString());
    	//MacAddress sourceMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());
    	//ipMacTables.put(sourceIp, sourceMac);
  
    	//查表，看控制器上是否有targetIp的mac
    	IpAddress targetIp = IpAddress.valueOf(InetAddress.getByAddress(arpPkt.getTargetProtocolAddress()));
    	log.info("Target ip: " + arpPkt.getTargetProtocolAddress());
    	//查看是否有记录
    	//if (hostService.getHostsByIp(IpAddress.valueOf(IpAddress.Version.INET, targetIp)) != null) {
    	if (ipMacTable.containsKey(targetIp)){
    		log.info("Here exists the target ip: " + arpPkt.getTargetProtocolAddress());
    		MacAddress targetMac = ipMacTable.get(targetIp);
    		sendArpReply(context, targetMac);
    		/*
    		//查看是否已在调度中
    		if (arpRequests.containsKey(targetIp)) {
    			ArpRequestRecord arpRequestRecord = new ArpRequestRecord(arpPkt, 
    					context.inPacket().receivedFrom().deviceId(), context.inPacket().receivedFrom().port(),
    					ethPkt.getSourceMAC(), ethPkt.getVlanID());
        		arpRequests.get(targetIp).add(arpRequestRecord);    			
    		} else {
    			HashSet<ArpRequestRecord> tmp /send_arp= new HashSet<ArpRequestRecord>();
    			tmp.add(new ArpRequestRecord(arpPkt, 
    					context.inPacket().receivedFrom().deviceId(), context.inPacket().receivedFrom().port(),
    					ethPkt.getSourceMAC(), ethPkt.getVlanID()));
    			arpRequests.put(targetIp, tmp);
    		}
    		*/
    	} else {
    		//没有记录，flood
    		log.info("Flood");
    		flood(context);
    	}    	
    }
  /*  
    private void handleArpReply(PacketContext context) throws UnknownHostException {
    	InboundPacket pkt = context.inPacket();
    	Ethernet ethPkt = pkt.parsed();
    	
    	ARP arpPkt = (ARP)ethPkt.getPayload();
    	
    	//将arp request包的sourceip和sourcemac学习到ipmactables里。
    	IpAddress sourceIp = IpAddress.valueOf(InetAddress.getByAddress(arpPkt.getSenderProtocolAddress()));
    	System.out.println("reply --->  source ip: " + sourceIp.toString());
    	MacAddress sourceMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());
    	System.out.println("reply --->  source mac: " + sourceMac.toString());
    	//ipMacTables.put(sourceIp, sourceMac);
    } */

    //处理arp request
  /*  private class ArpRequestTimerTask extends TimerTask{

		@Override
		public void run() {
			System.out.println("Schedule start");
			Iterator iter = arpRequests.entrySet().iterator();
			while (iter.hasNext()) {
				System.out.println("step1");
				Map.Entry<IpAddress, HashSet<ArpRequestRecord> > entry = (Entry<IpAddress, HashSet<ArpRequestRecord>>)iter.next();
				IpAddress targetIp = entry.getKey();
				System.out.println("target ip: " + targetIp.toString());
				//If there exists the recode in ip_mac tables
				
				if (hostService.getHostsByIp(targetIp) != null) {
					System.out.println("step2");
					//long targetMac = ipMacTables.get(targetIp);
					final Iterable<Host> hosts = hostService.getHostsByIp(targetIp);
					Iterator hostIter = hosts.iterator();
					MacAddress targetMac = null;
					while (hostIter.hasNext()) {
						targetMac = ((Host)hostIter.next()).mac();
					}
					if (targetMac != null) {
						System.out.println("step3");
						HashSet<ArpRequestRecord> arpRequest = entry.getValue();				
						//send reply
						Iterator setIter = arpRequest.iterator();
						while (setIter.hasNext()) {
							System.out.println("Send arp reply");
							sendArpReply(targetMac, (ArpRequestRecord)setIter.next());
						}	
						//After sending reply message, removing corresponding record
						arpRequests.remove(targetIp);
					}
				}    	ArpRequestRecord sourceRecord = new ArpRequestRecord(arpPkt, pkt.receivedFrom().deviceId(), 
    			pkt.receivedFrom().port(), ethPkt.getSourceMAC(), ethPkt.getVlanID());
			}
			System.out.println("schedule stop");
		}
    	
    }  */
    
    //send a packet out
    private void packetOut (PacketContext context, PortNumber portNumber) {
    	context.treatmentBuilder().setOutput(portNumber);
    	context.send();
    }
    
    //flood
    private void flood (PacketContext context) {
    	packetOut(context, PortNumber.FLOOD);
    }
    
    //send reply
    private void sendArpReply (PacketContext context, MacAddress targetMac) {
    	InboundPacket pkt = context.inPacket();
    	Ethernet ethPkt = pkt.parsed();
    	ARP arpPkt = (ARP)ethPkt.getPayload();
    	
    	//construct a arp reply packet
    	ARP arpReply = (ARP)arpPkt.clone();    	
    	arpReply.setOpCode(ARP.OP_REPLY);
    	arpReply.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());
    	arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
    	arpReply.setSenderProtocolAddress(arpPkt.getTargetProtocolAddress());
    	arpReply.setSenderHardwareAddress(targetMac.toBytes());
    	
    	//Ethernet frame
    	Ethernet ethReply = new Ethernet();
    	ethReply.setSourceMACAddress(targetMac);
    	ethReply.setDestinationMACAddress(ethPkt.getSourceMAC());
    	ethReply.setEtherType(Ethernet.TYPE_ARP);
    	ethReply.setVlanID(ethPkt.getVlanID());
    	ethReply.setPayload(arpReply);
    	
    	//packetout the reply
    	TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
    	builder.setOutput(pkt.receivedFrom().port());
    	packetService.emit(new DefaultOutboundPacket(pkt.receivedFrom().deviceId(), builder.build(), 
    			ByteBuffer.wrap(ethReply.serialize())));
    	
    }
    
    //arp request statistics
    private void arpCount(PacketContext context) throws UnknownHostException {
    	InboundPacket pkt = context.inPacket();
    	Ethernet ethPkt = pkt.parsed();
    	ARP arpPkt = (ARP)ethPkt.getPayload();
    	
    	IpAddress sourceIp = IpAddress.valueOf(InetAddress.getByAddress(arpPkt.getSenderProtocolAddress()));    	
    	ArpRecord sourceRecord = new ArpRecord(arpPkt, pkt.receivedFrom().deviceId(), 
    			pkt.receivedFrom().port());
    	if (!arpFrequence.containsKey(sourceRecord)) {
    		arpFrequence.put(sourceRecord, 0);
    	}
    	int count = arpFrequence.get(sourceRecord);
    	arpFrequence.put(sourceRecord, ++count);
    }
    
    private class AntiAttackTimerTask extends TimerTask {

		@Override
		public void run() {
			Iterator countIter = arpFrequence.entrySet().iterator();
			while (countIter.hasNext()) {
				Map.Entry<ArpRecord, Integer> entry = (Entry<ArpRecord, Integer>) countIter.next();
				if (entry.getValue() > REQUEST_THRESHOLD) {
					sendAttackDrop(entry.getKey());
					System.out.println("A attack detected from "+ MacAddress.valueOf(entry.getKey().getArp().getSenderHardwareAddress()).toString());
				}
			}
			arpFrequence.clear();
		}
    	
    }
    
    private void sendAttackDrop(ArpRecord arpRecord) {
    	TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
    	selector.matchEthType(Ethernet.TYPE_ARP);
    	selector.matchEthSrc(MacAddress.valueOf(arpRecord.getArp().getSenderHardwareAddress()));
    	//selector.matchEthType(Ethernet.TYPE_IPV4);
    	//selector.matchInPort(PortNumber.portNumber(1));
    	//selector.matchVlanId(VlanId.vlanId(arpRecord.getVlanId()));
    	
    	TrafficTreatment treatement = DefaultTrafficTreatment.builder().drop().build();
//    	TrafficTreatment treatement = DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(2))
//    			.build();
    	
    	ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
    										.withSelector(selector.build())
    										.withTreatment(treatement)
    										.withPriority(DROP_PRORITY)
    										.withFlag(Flag.VERSATILE)
    										.fromApp(appId)
    										.makeTemporary(DROP_TIMEOUT)
    										.add();       //add() is add, remove() is remove
    	//flowObjectiveService.forward(arpRecord.getSwitchId(), forwardingObjective);
    	flowServiceForward(arpRecord.getSwitchId(), forwardingObjective);
    }
    
  //Used to apply flowRule
    private void flowServiceForward(DeviceId deviceId, ForwardingObjective forwardingObjective) {
        Driver driver = driverService.getDriver(DRIVER_NAME);
        Pipeliner pipeLiner = driver.createBehaviour(new DefaultDriverData(driver, deviceId), Pipeliner.class);
        if (pipeLiner != null) {
            final PipelinerContext context = new InnerPipelineContext();
            pipeLiner.init(deviceId, context);
            pipeLiner.forward(forwardingObjective);
        }
    }

    // Processing context for initializing pipeline driver behaviours.
    private class InnerPipelineContext implements PipelinerContext {
        @Override
        public ServiceDirectory directory() {
            return serviceDirectory;
        }

        @Override
        public FlowObjectiveStore store() {
            return flowObjectiveStore;
        }
    }

	@Override
	public Map<IpAddress, MacAddress> getIpMacTable() {
		return this.ipMacTable;
	}

	@Override
	public void setIpMacTable(IpAddress ip, MacAddress mac) {
		this.ipMacTable.put(ip, mac);		
	}
}







