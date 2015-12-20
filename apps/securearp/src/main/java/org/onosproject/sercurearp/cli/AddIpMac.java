package org.onosproject.sercurearp.cli;

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

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.MplsIntent;
import org.onosproject.securearp.SecureArpService;

import java.util.List;
import java.util.Optional;

/**
 * Installs MPLS intents.
 */
@Command(scope = "onos", name = "add-ipmac", description = "Installs mpls connectivity intent")
public class AddIpMac extends AbstractShellCommand {

    @Argument(index = 0, name = "ip",
            description = "Host ip",
            required = true,
            multiValued = false)
    private String ipString = null;

    @Argument(index = 1, name = "mac",
            description = "Host mac",
            required = true,
            multiValued = false)
    private String macString = null;
    
    private SecureArpService service;

    @Override
    protected void execute() {
        IpAddress ip = IpAddress.valueOf(ipString);
        MacAddress mac = MacAddress.valueOf(macString);
        
        service = get(SecureArpService.class);
        
        service.setIpMacTable(ip, mac);
        
    }

}
