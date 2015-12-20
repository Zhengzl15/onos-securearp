package org.onosproject.securearp;

import java.util.Map;

import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;

public interface SecureArpService {

	public Map<IpAddress, MacAddress> getIpMacTable ();
	
	public void setIpMacTable (IpAddress ip, MacAddress mac);
}