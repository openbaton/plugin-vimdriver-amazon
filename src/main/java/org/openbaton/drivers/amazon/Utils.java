package org.openbaton.drivers.amazon;

import com.amazonaws.services.ec2.model.*;
import java.util.*;
import org.openbaton.catalogue.nfvo.Server;
import org.openbaton.catalogue.nfvo.images.AWSImage;
import org.openbaton.catalogue.nfvo.images.NFVImage;
import org.openbaton.catalogue.nfvo.networks.AWSNetwork;
import org.openbaton.catalogue.nfvo.networks.BaseNetwork;

class Utils {

  static org.openbaton.catalogue.nfvo.Server getServer(Instance instance, List<BaseNetwork> nets) {
    Server server = new Server();
    server.setExtId(instance.getInstanceId());
    server.setStatus(instance.getState().getName());
    server.setHypervisorHostName(instance.getHypervisor());
    server.setCreated(instance.getLaunchTime());
    NFVImage image = new NFVImage();
    image.setExtId(instance.getImageId());
    server.setImage(image);
    if (instance.getTags() != null) {
      for (Tag tag : instance.getTags()) {
        if (tag.getKey().equals("Name")) {
          server.setName(tag.getValue());
          server.setHostName(tag.getValue());
          server.setInstanceName(tag.getValue());
        }
      }
    }
    HashMap<String, String> netNameId = new HashMap<>();
    for (BaseNetwork net : nets) {
      netNameId.put(net.getExtId(), net.getName());
    }
    String primarySubnetId = instance.getSubnetId();
    String primarySubnetName = "";
    for (BaseNetwork net : nets) {
      if (net.getExtId().equals(primarySubnetId)) {
        primarySubnetName = net.getName();
      }
    }
    if (instance.getPublicIpAddress() != null) {
      HashMap<String, String> floatingIps = new HashMap<>();
      floatingIps.put(primarySubnetName, instance.getPublicIpAddress());
      server.setFloatingIps(floatingIps);
    }
    if (instance.getPrivateIpAddress() != null) {
      HashMap<String, List<String>> ips = new HashMap<>();
      List<String> privateIps = new ArrayList<>();
      List<InstanceNetworkInterface> netInt = instance.getNetworkInterfaces();
      for (InstanceNetworkInterface inter : netInt) {
        for (InstancePrivateIpAddress adress : inter.getPrivateIpAddresses()) {
          privateIps.add(adress.getPrivateIpAddress());
        }
        ips.put(netNameId.get(inter.getSubnetId()), privateIps);
      }

      server.setIps(ips);
    }
    return server;
  }

  /*static org.openbaton.catalogue.nfvo.Network getNetworkFromVpc(Vpc vpc, List<com.amazonaws.services.ec2.model.Subnet> subnets) {
      Network network = new Network();
      network.setExtId(vpc.getVpcId());
      Set<Subnet> nfvoSubnets = new HashSet<>();
      for (com.amazonaws.services.ec2.model.Subnet subnet : subnets) {
          if (subnet.getVpcId().equals(vpc.getVpcId())) {
              nfvoSubnets.add(getSubnet(subnet));
          }
      }
      network.setSubnets(nfvoSubnets);
      return network;
  }*/

  /**
   * Converts aws subnet to nfvo network
   *
   * <p>AWS EC2 VPCs do not have internal networks. Subnet is converted to network with one subnet
   * in order to map the resource as precisely as possible Is the subnet has not name tag, which is allowed
   * in AWS the id will be assigned to name to ensure consistency
   *
   * @param subnet aws subnet
   * @return created nfvo network
   */
  static org.openbaton.catalogue.nfvo.networks.AWSNetwork getNetworkFromSubnet(
      com.amazonaws.services.ec2.model.Subnet subnet) {
    AWSNetwork nfvoNetwork = new AWSNetwork();
    nfvoNetwork.setExtId(subnet.getSubnetId());
    for (Tag tag : subnet.getTags()) {
      if (tag.getKey().equals("Name")) {
        nfvoNetwork.setName(tag.getValue());
      }
    }
    if (nfvoNetwork.getName() == null || nfvoNetwork.getName().isEmpty() || nfvoNetwork.equals("")) {
      nfvoNetwork.setName(subnet.getSubnetId());
    }
    nfvoNetwork.setIpv4cidr(subnet.getCidrBlock());
    nfvoNetwork.setAvZone(subnet.getAvailabilityZone());
    nfvoNetwork.setExtId(subnet.getSubnetId());
    nfvoNetwork.setVpcId(subnet.getVpcId());
    nfvoNetwork.setState(subnet.getState());
    nfvoNetwork.setDef(subnet.getDefaultForAz());
    return nfvoNetwork;
  }

  static org.openbaton.catalogue.nfvo.images.AWSImage getImage(
      com.amazonaws.services.ec2.model.Image image) {
    AWSImage nfvoImage = new AWSImage();
    nfvoImage.setName(image.getName());
    nfvoImage.setExtId(image.getImageId());
    nfvoImage.setHypervisor(image.getHypervisor());
    nfvoImage.setDescription(image.getDescription());
    nfvoImage.setImageOwner(image.getImageOwnerAlias());
    nfvoImage.setPublic(image.getPublic());
    return nfvoImage;
  }
}
