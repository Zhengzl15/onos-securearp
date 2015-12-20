/*
 * Copyright 2015 Open Networking Laboratory
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
package org.onosproject.sercurearp.cli;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onosproject.cli.AbstractShellCommand;
import java.util.Map;

import org.onosproject.securearp.SecureArpService;


@Command(scope = "onos", name = "show-ipmac",
        description = "show ipmac table")
public class ShowIpMac extends AbstractShellCommand {

    @Argument(index = 0, name = "ipmac", description = "No description",
            required = false, multiValued = false)
    //String uri = null;

    private static final String FMT = "ip=%s, mac=%s";
    private Map<IpAddress, MacAddress> ipMacTable;
    private SecureArpService service;

    @Override
    protected void execute() {
        service = get(SecureArpService.class);
        ipMacTable = service.getIpMacTable();
        
        if (ipMacTable.size() == 0) {
        	print("No record");
        	return;
        }
        
        for (Map.Entry<IpAddress, MacAddress> entry : ipMacTable.entrySet()) {
        	print(FMT, entry.getKey(), entry.getValue());
        }

    }
}
