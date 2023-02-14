/*
 * Copyright 2022-present Open Networking Foundation
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
package nctu.winlab.bridge;

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
// import org.onosproject.net.flowobjective.FlowObjectiveService;
// import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.PacketService;
// import org.onosproject.net.topology.TopologyService;
// import org.onosproject.ui.topo.TopoConstants;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.remoteserviceadmin.namespace.DistributionNamespace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

import java.util.Map;
import java.util.Optional;

import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.core.ApplicationId;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    /** Some configurable property. */
    private String someProperty;

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private static final int DEAFULT_TIMEOUT = 30;
    private static final int DEFAULT_PRIORITY = 30;

    protected Map<DeviceId, Map<MacAddress, PortNumber>> macTables = Maps.newConcurrentMap();
    private ApplicationId appId;
    private PacketProcessor processor;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        log.info("Started===========");
        appId = coreService.getAppId("nctu.winlab.app");

        processor = new LearningBridgeProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        // only request IPV4 and ARP
        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(),
                                    PacketPriority.REACTIVE,
                                    appId, Optional.empty());
        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                                    PacketPriority.REACTIVE,
                                    appId, Optional.empty());
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped===========");
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);
        
        // withdraw packet
        packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(),
                                    PacketPriority.REACTIVE,
                                    appId, Optional.empty());
        packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                                    PacketPriority.REACTIVE,
                                    appId, Optional.empty());
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    // define a processor to deal with packet
    private class LearningBridgeProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            log.info("Enter process " + context.toString());
            initMacTable(context.inPacket().receivedFrom());
            forwarding(context);
        }

        private void initMacTable(ConnectPoint cp) {
            macTables.putIfAbsent(cp.deviceId(), Maps.newConcurrentMap());
        }

        public void flooding(PacketContext context) {
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        }

        public void forwarding(PacketContext context) {
            Short type = context.inPacket().parsed().getEtherType();

            if (type != Ethernet.TYPE_IPV4 && type != Ethernet.TYPE_ARP) {
                return;
            }

            ConnectPoint cp = context.inPacket().receivedFrom();
            DeviceId switchId = cp.deviceId();
            Map<MacAddress, PortNumber> macTable = macTables.get(switchId);
            MacAddress srcMac = context.inPacket().parsed().getSourceMAC();
            MacAddress dstMac = context.inPacket().parsed().getDestinationMAC();
            macTable.put(srcMac, cp.port());
            PortNumber outPort = macTable.get(dstMac);

            log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                switchId, srcMac, cp.port());
            if (outPort != null) {
                
                TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
                TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
                // FlowRule rule = DefaultFlowRule.builder()
                //                 .withSelector(selector.matchEthSrc(srcMac).matchEthDst(dstMac).build())
                //                 .withTreatment(treatment.setOutput(outPort).build())
                //                 .forDevice(switchId)
                //                 .withPriority(DEFAULT_PRIORITY)
                //                 .makeTemporary(DEAFULT_TIMEOUT)
                //                 .fromApp(appId).build();

                // flowRuleService.applyFlowRules(rule);

                ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                        .withSelector(selector.matchEthSrc(srcMac).matchEthDst(dstMac).build())
                        .withTreatment(treatment.setOutput(outPort).build())
                        .withPriority(DEFAULT_PRIORITY)
                        .makeTemporary(DEAFULT_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .fromApp(appId)
                        .add();

                flowObjectiveService.forward(switchId, forwardingObjective);

                context.treatmentBuilder().setOutput(outPort);
                context.send();
                log.info("MAC address `{}` is matched on `{}`. Install a flow rule.", dstMac, switchId);

            } else {
                flooding(context);
                log.info("MAC address `{}` is missed on `{}`. Flood the packet.", dstMac, switchId);
            }
        }
    }

}
