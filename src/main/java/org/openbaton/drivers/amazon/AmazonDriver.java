/*
 * Copyright (c) 2017 Open Baton (http://www.openbaton.org)
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

package org.openbaton.drivers.amazon;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.*;
import com.amazonaws.services.ec2.model.InstanceType;
import com.amazonaws.services.ec2.model.Subnet;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base64;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.*;
import org.openbaton.catalogue.nfvo.images.AWSImage;
import org.openbaton.catalogue.nfvo.images.BaseNfvImage;
import org.openbaton.catalogue.nfvo.networks.AWSNetwork;
import org.openbaton.catalogue.nfvo.networks.BaseNetwork;
import org.openbaton.catalogue.nfvo.viminstances.AmazonVimInstance;
import org.openbaton.catalogue.nfvo.viminstances.BaseVimInstance;
import org.openbaton.catalogue.security.Key;
import org.openbaton.exceptions.VimDriverException;
import org.openbaton.exceptions.VimException;
import org.openbaton.plugin.PluginStarter;
import org.openbaton.vim.drivers.interfaces.VimDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AmazonDriver extends VimDriver {

  private static Logger log = LoggerFactory.getLogger(AmazonDriver.class);

  public AmazonDriver() {
    super();
  }

  public static void main(String[] args)
      throws NoSuchMethodException, IOException, InstantiationException, TimeoutException,
          IllegalAccessException, InvocationTargetException, InterruptedException {
    if (args.length == 4) {
      log.info("Starting the plugin with CUSTOM parameters: ");
      log.info("name: " + args[0]);
      log.info("brokerIp: " + args[1]);
      log.info("port: " + args[2]);
      log.info("consumers: " + args[3]);
      PluginStarter.registerPlugin(
          AmazonDriver.class,
          args[0],
          args[1],
          Integer.parseInt(args[2]),
          Integer.parseInt(args[3]));
    } else {
      log.info("Starting the plugin with DEFAULT parameters");
      log.info("name: amazon");
      log.info("brokerIp: localhost");
      log.info("port: 5672");
      log.info("consumers: 10");
      PluginStarter.registerPlugin(AmazonDriver.class, "amazon", "localhost", 5672, 10);
    }
  }

  private String changeHostname(String userdata, String hostname) {
    String trimmedUserdata = userdata.trim();
    String newData;
    Pattern pattern = Pattern.compile(Pattern.quote("echo hostname=$hn"));
    Matcher matcher = pattern.matcher(trimmedUserdata);
    String start = "";
    String end = "";
    if (matcher.find()) {
      start = trimmedUserdata.substring(0, matcher.start());
      end = trimmedUserdata.substring(matcher.end());
      newData = start + "echo hostname=" + hostname + end;
    } else {
      newData = trimmedUserdata;
    }

    return newData;
  }

  /**
   * Creates a client for AmazonEC2 communication fro vim instance data username: access key id
   * password: secret key
   *
   * @param vimInstance the vim description
   * @return amazonEc2 client ready to handle requests
   * @throws VimDriverException if one of the arguments is not correctly set
   */
  private AmazonEC2 createClient(AmazonVimInstance vimInstance) throws VimDriverException {
    BasicAWSCredentials awsCreds =
        new BasicAWSCredentials(vimInstance.getAccessKey(), vimInstance.getSecretKey());
    Regions regions;
    AmazonEC2 client;
    try {
      regions = Regions.fromName(vimInstance.getRegion());
      client =
          AmazonEC2ClientBuilder.standard()
              .withRegion(regions)
              .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
              .build();
    } catch (IllegalArgumentException e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
    return client;
  }

  @java.lang.Override
  public Server launchInstance(
      BaseVimInstance vimInstanceBase,
      String name,
      String image,
      String flavor,
      String keypair,
      java.util.Set<VNFDConnectionPoint> networks,
      java.util.Set<String> secGroup,
      String userData)
      throws VimDriverException {
    System.out.println(userData);
    log.info("Launching instance " + name);
    Server server = null;
    try {
      AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
      String changeUserData = changeHostname(userData, name);
      AmazonEC2 client = createClient(vimInstance);
      Gson gson = new Gson();
      String oldVNFDCP = gson.toJson(networks);
      Set<VNFDConnectionPoint> newNetworks =
          gson.fromJson(oldVNFDCP, new TypeToken<Set<VNFDConnectionPoint>>() {}.getType());
      RunInstancesRequest runInstancesRequest = new RunInstancesRequest();
      String vpcId = getVpcsMap(vimInstance).get(vimInstance.getVpcName());
      if (vpcId == null) {
        throw new VimDriverException("No such VPC " + vimInstance.getVpcName() + " exists");
      }
      log.info("Found the VPC ID: " + vpcId);
      byte[] encodedData = Base64.encodeBase64(changeUserData.getBytes());
      List<DeploymentFlavour> flavours = listFlavors(vimInstance);
      log.info("Listed flavours");
      List<BaseNetwork> presentSubnets = listNetworks(vimInstance);
      log.info("Listed subents");
      Collection<InstanceNetworkInterfaceSpecification> inters = new ArrayList<>();
      Set<String> groupIds = getSecurityIdFromName(secGroup, client, vimInstance);
      log.info("Retrieved security ids");
      int deviceIndex = 0;
      List<AWSNetwork> relevantSubnets = searchForRelevantSubnets(presentSubnets, newNetworks);
      if (relevantSubnets.size() < 2) {
        inters.add(createInterfaceWithPublicIp(relevantSubnets.get(0), 0, groupIds));
      } else {
        for (BaseNetwork net : relevantSubnets) {
          inters.add(createInterface(net, deviceIndex, groupIds));
          deviceIndex++;
          log.info("Interface " + deviceIndex);
        }
      }
      log.info("Created interfaces");
      String amiID = imageExistsOnAWS(image, client);
      String instanceType = "";
      for (DeploymentFlavour flavour : flavours) {
        if (flavour.getFlavour_key().equals(flavor)) {
          instanceType = flavour.getFlavour_key();
        }
      }
      if (amiID == null) {
        throw new VimException("Not found image " + image + " on VIM " + vimInstance.getName());
      }
      log.info("The ID of the image is " + amiID);
      if (instanceType.equals("")) {
        throw new VimException("Not found type " + flavor + " on VIM " + vimInstance.getName());
      }
      log.info("Instance type is " + instanceType);
      log.info("Sending launch request");
      runInstancesRequest
          .withImageId(amiID)
          .withInstanceType(instanceType)
          .withMinCount(1)
          .withMaxCount(1)
          .withUserData(new String(encodedData, "UTF8"))
          .withNetworkInterfaces(inters)
          .withKeyName(vimInstance.getKeyPair());
      RunInstancesResult result = client.runInstances(runInstancesRequest);
      log.info("Launched instance " + result.getReservation().getInstances().get(0).toString());
      String id = result.getReservation().getInstances().get(0).getInstanceId();
      log.info("Assigning name to instance " + id);
      List<Tag> tags = new ArrayList<>();
      Tag tag = new Tag();
      tag.setKey("Name");
      tag.setValue(name);
      tags.add(tag);
      CreateTagsRequest tagsRequest = new CreateTagsRequest().withTags(tags).withResources(id);
      client.createTags(tagsRequest);
      log.info("Instance is up, handling networking");
      if (networks.size() > 1) {
        server = waitForInstance(name, vimInstance);
        setupInstanceNetwork(client, server);
      }
      List<Server> servers = listServer(vimInstance);
      for (Server ser : servers) {
        if (ser != null && ser.getHostName().equals(name)) {
          server = ser;
        }
      }
    } catch (VimException e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    } catch (UnsupportedEncodingException e) {
      throw new VimDriverException(e.getMessage());
    } catch (AmazonClientException e) {
      log.info("Amazon has thrown an exception: " + e.getMessage());
      throw new VimDriverException(e.getMessage());
    } catch (InterruptedException e) {
      throw new VimDriverException(e.getMessage());
    }
    log.info("Instance " + name + " launched");
    return server;
  }

  @Override
  public BaseVimInstance refresh(BaseVimInstance vimInstance) throws VimDriverException {
    AmazonVimInstance amazon = (AmazonVimInstance) vimInstance;
    List<BaseNfvImage> newImages = listImages(vimInstance);
    if (amazon.getImages() == null) {
      amazon.setImages(new HashSet<>());
    }
    amazon.removeAllImages();
    amazon.addAllImages(newImages);

    List<BaseNetwork> newNetworks = listNetworks(vimInstance);

    if (amazon.getNetworks() == null) {
      amazon.setNetworks(new HashSet<>());
    }
    amazon.removeAllNetworks();
    amazon.addAllNetworks(newNetworks);
    amazon.setVpcId(getVpcsMap(amazon).get(amazon.getVpcName()));

    List<DeploymentFlavour> newFlavors = listFlavors(vimInstance);
    if (amazon.getFlavours() == null) {
      amazon.setFlavours(new HashSet<>());
    }
    amazon.removeAllFlavours();
    amazon.addAllFlavours(newFlavors);
    return (BaseVimInstance) amazon;
  }

  private Server waitForInstance(String name, BaseVimInstance vimInstance)
      throws VimDriverException, InterruptedException {
    int timeOut = Integer.parseInt(properties.getProperty("launchTimeout"));
    log.info("Waiting for instance. LaunchTimeout is " + timeOut);
    int waitTime = 4;
    while (waitTime < timeOut) {
      List<Server> servers = listServer(vimInstance);
      for (Server ser : servers) {
        if (ser != null && ser.getHostName().equals(name) && ser.getStatus().equals("running")) {
          return ser;
        }
        try {
          TimeUnit.SECONDS.sleep(waitTime);
          waitTime = waitTime * 2;
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }
    throw new VimDriverException(
        "Launch Timeout reached, seems that the instance never went into running status");
  }

  private void setupInstanceNetwork(AmazonEC2 client, Server server) {
    List<Address> freeAddresses = getUnallocatedAddresses(client);
    List<NetworkInterface> instanceInterfaces =
        listInterfaceByAttachment(client, server.getExtId());

    if (freeAddresses.size() < instanceInterfaces.size()) {
      allocateElasticIps(client, instanceInterfaces.size() - freeAddresses.size());
    }
    freeAddresses = getUnallocatedAddresses(client);
    int i = 0;
    for (NetworkInterface inter : instanceInterfaces) {
      AssociateAddressRequest addrReq =
          new AssociateAddressRequest()
              .withNetworkInterfaceId(inter.getNetworkInterfaceId())
              .withAllocationId(freeAddresses.get(i).getAllocationId())
              .withAllowReassociation(false);
      client.associateAddress(addrReq);
      i++;
    }
  }

  private void allocateElasticIps(AmazonEC2 client, int number) {
    log.info("Allocating " + number + " elastic ips");
    AllocateAddressRequest req = new AllocateAddressRequest();
    for (int i = 0; i < number; i++) {
      client.allocateAddress(req);
    }
  }

  private List<Address> getUnallocatedAddresses(AmazonEC2 client) {
    DescribeAddressesRequest addReq = new DescribeAddressesRequest();
    DescribeAddressesResult re = client.describeAddresses(addReq);
    List<Address> unAllockAddrs = new ArrayList<>();
    for (Address addr : re.getAddresses()) {
      if (addr.getAssociationId() == null) {
        unAllockAddrs.add(addr);
      }
    }
    return unAllockAddrs;
  }

  /**
   * Get the interfaces attached to a certain VM
   *
   * @param client amazonec2 client
   * @param instanceId id of the vm
   * @return list of interfaces
   */
  private List<NetworkInterface> listInterfaceByAttachment(AmazonEC2 client, String instanceId) {
    Filter filter = new Filter();
    filter.setName("attachment.instance-id");
    filter.setValues(Collections.singletonList(instanceId));
    Filter filter1 = new Filter();
    //      filter1.setName("attachment.device-index");
    //      filter1.setValues(Collections.singletonList("0"));
    //
    //      DescribeNetworkInterfacesRequest req = new DescribeNetworkInterfacesRequest().withFilters(Arrays.asList(filter, filter1));
    DescribeNetworkInterfacesRequest req =
        new DescribeNetworkInterfacesRequest().withFilters(Collections.singletonList(filter));
    DescribeNetworkInterfacesResult res = client.describeNetworkInterfaces(req);
    return res.getNetworkInterfaces();
  }

  private List<InternetGateway> getInternetGatewaysByVPC(AmazonEC2 client, String vpcId) {
    Filter filter = new Filter();
    filter.setName("attachment.vpc-id");
    filter.setValues(Collections.singletonList(vpcId));
    DescribeInternetGatewaysRequest request = new DescribeInternetGatewaysRequest();
    request.setFilters(Collections.singletonList(filter));
    DescribeInternetGatewaysResult result = client.describeInternetGateways(request);
    return result.getInternetGateways();
  }

  /**
   * Creates the internet gateway in a particular vpc
   *
   * @param client amazon client to make calls to api
   * @param vpcId the id of the VPC where gateway should be attached
   * @return createdgateway data
   */
  private InternetGateway createAndAttachInternetGateway(AmazonEC2 client, String vpcId) {
    CreateInternetGatewayRequest request = new CreateInternetGatewayRequest();
    CreateInternetGatewayResult result = client.createInternetGateway(request);
    InternetGateway gateway = result.getInternetGateway();
    AttachInternetGatewayRequest attach =
        new AttachInternetGatewayRequest()
            .withVpcId(vpcId)
            .withInternetGatewayId(gateway.getInternetGatewayId());
    client.attachInternetGateway(attach);
    return gateway;
  }

  /**
   * Checks if the image exists inside AWS and returns its ID
   *
   * @param nameId Either name or the id of the image inside AWS
   * @param client AmazonEC2 client to make a request
   * @return id of the image or null if no image is there
   */
  private String imageExistsOnAWS(String nameId, AmazonEC2 client) throws AmazonClientException {
    Filter filter = new Filter();
    filter.setName("name");
    filter.setValues(Arrays.asList(nameId));
    DescribeImagesRequest describeImagesRequest = new DescribeImagesRequest();
    describeImagesRequest.setFilters(Arrays.asList(filter));
    DescribeImagesResult describeImagesResult = client.describeImages(describeImagesRequest);
    if (describeImagesResult.getImages().size() > 0) {
      return describeImagesResult.getImages().get(0).getImageId();
    }
    filter.setName("image-id");
    filter.setValues(Arrays.asList(nameId));
    describeImagesRequest = new DescribeImagesRequest();
    describeImagesRequest.setFilters(Arrays.asList(filter));
    describeImagesResult = client.describeImages(describeImagesRequest);
    if (describeImagesResult.getImages().size() > 0) {
      return describeImagesResult.getImages().get(0).getImageId();
    }
    return null;
  }

  /**
   * Creates an interface for the instance in order to connect to subnet. Does not assign floating
   * ip, this method is used in case multiple interfaces are supposed to be created for on instance.
   * Elastic ips are then assgined after creation.
   *
   * @param net subnet inside AWS represented through NFVO network
   * @param deviceIndex device index for the interface is required by AWS
   * @param secIDs security group ID
   * @return the list of interfaces
   */
  private InstanceNetworkInterfaceSpecification createInterface(
      BaseNetwork net, int deviceIndex, Set<String> secIDs) {
    InstanceNetworkInterfaceSpecification interSpec =
        new InstanceNetworkInterfaceSpecification()
            .withDeleteOnTermination(true)
            .withSubnetId(net.getExtId())
            .withGroups(secIDs)
            .withDeviceIndex(deviceIndex);
    log.info("Device index" + deviceIndex);
    return interSpec;

    /*String floatingIp = "";
    for (VNFDConnectionPoint cp : cps) {
      if (net.getName().equals(cp.getVirtual_link_reference())) {
        floatingIp = cp.getFloatingIp();
      }
    }*/

  }

  /**
   * Creates an interface for the instance in order to connect to subnet and assigns public ip to it
   * connecting the instance to internet. Used only if the instance has no more than one network
   * interface. It is made in order to conserve the limited amount of elastic ips on AWS (5 only
   * generally) and not use them if not necessary.
   *
   * @param net subnet inside AWS represented through NFVO network
   * @param deviceIndex device index for the interface is required by AWS
   * @param secIDs security group ID
   * @return
   */
  private InstanceNetworkInterfaceSpecification createInterfaceWithPublicIp(
      BaseNetwork net, int deviceIndex, Set<String> secIDs) {
    InstanceNetworkInterfaceSpecification interSpec =
        new InstanceNetworkInterfaceSpecification()
            .withDeleteOnTermination(true)
            .withSubnetId(net.getExtId())
            .withGroups(secIDs)
            .withDeviceIndex(deviceIndex)
            .withAssociatePublicIpAddress(true);
    log.info("Device index" + deviceIndex);
    return interSpec;

    /*String floatingIp = "";
    for (VNFDConnectionPoint cp : cps) {
      if (net.getName().equals(cp.getVirtual_link_reference())) {
        floatingIp = cp.getFloatingIp();
      }
    }*/

  }

  /**
   * Crosscheck the connection points with subnets and return the relevant ones
   *
   * @param nets All subnets
   * @param cps All connection points
   * @return subnets the instance is connected to
   */
  private List<AWSNetwork> searchForRelevantSubnets(
      List<BaseNetwork> nets, Set<VNFDConnectionPoint> cps) {
    ArrayList<VNFDConnectionPoint> cpList = new ArrayList<>(cps);
    Collections.sort(
        cpList,
        new Comparator<VNFDConnectionPoint>() {
          @Override
          public int compare(VNFDConnectionPoint t, VNFDConnectionPoint t1) {
            if (t.getInterfaceId() > t1.getInterfaceId()) {
              return -1;
            }
            if (t.getInterfaceId() == t1.getInterfaceId()) {
              return 0;
            } else {
              return 1;
            }
          }
        });
    List<AWSNetwork> relevantSubnets = new ArrayList<>();
    for (VNFDConnectionPoint cp : cpList) {
      for (BaseNetwork net : nets) {
        if (net.getName().equals(cp.getVirtual_link_reference())) {
          relevantSubnets.add((AWSNetwork) net);
        }
      }
    }

    return relevantSubnets;
  }

  /**
   * Get the ids of the security groups by names of the security groups
   *
   * @param groupNames Group names that come from NFVO
   * @param client ec2 client
   * @param vimInstanceBase vim description
   * @return list of the security groups ids
   * @throws VimDriverException in case there is no VPC with such name or one of the security groups
   *     does not exits
   */
  private Set<String> getSecurityIdFromName(
      Set<String> groupNames, AmazonEC2 client, BaseVimInstance vimInstanceBase)
      throws VimDriverException, AmazonClientException {
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getVpcName());
    if (vpcId == null) {
      throw new VimDriverException(
          "No such VPC " + ((AmazonVimInstance) vimInstance).getVpcName() + " exists");
    }
    Filter filter = new Filter();
    filter.setName("vpc-id");
    filter.setValues(Arrays.asList(vpcId));
    DescribeSecurityGroupsRequest req = new DescribeSecurityGroupsRequest();
    req.setFilters(Arrays.asList(filter));
    DescribeSecurityGroupsResult res = client.describeSecurityGroups(req);
    Set<String> groupIds = new HashSet<>();
    for (String name : groupNames) {
      String id = null;
      for (SecurityGroup group : res.getSecurityGroups()) {
        if (name.equals(group.getGroupName())) {
          id = group.getGroupId();
        }
      }
      if (id != null) {
        groupIds.add(id);
      } else {
        throw new VimDriverException(
            "No group " + name + "exists on VPC " + ((AmazonVimInstance) vimInstance).getVpcName());
      }
    }

    return groupIds;
  }

  @java.lang.Override
  public java.util.List<BaseNfvImage> listImages(BaseVimInstance vimInstance)
      throws VimDriverException {
    try {
      AmazonEC2 client = createClient((AmazonVimInstance) vimInstance);
      String keyWord = properties.getProperty("image-key-word", "*");
      String keyWords[] = keyWord.split(",");
      for (int i = 0; i < keyWords.length; i++) {
        keyWords[i] = "*" + keyWords[i] + "*";
      }
      Filter filter = new Filter();
      filter.setName("name");
      filter.setValues(Arrays.asList(keyWords));
      DescribeImagesRequest describeImagesRequest = new DescribeImagesRequest();
      describeImagesRequest.setFilters(Arrays.asList(filter));
      DescribeImagesResult describeImagesResult = client.describeImages(describeImagesRequest);
      List<BaseNfvImage> images = new ArrayList<>();
      for (Image image : describeImagesResult.getImages()) {
        images.add(Utils.getImage(image));
      }
      filter.setName("image-id");
      filter.setValues(Arrays.asList(keyWords));
      describeImagesRequest = new DescribeImagesRequest();
      describeImagesRequest.setFilters(Arrays.asList(filter));
      describeImagesResult = client.describeImages(describeImagesRequest);
      for (Image image : describeImagesResult.getImages()) {
        images.add(Utils.getImage(image));
      }

      return images;
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @java.lang.Override
  public java.util.List<Server> listServer(BaseVimInstance vimInstanceBase)
      throws VimDriverException {
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    try {
      List<Server> servers = new ArrayList<>();
      AmazonEC2 client = createClient(vimInstance);
      String vpcId = getVpcsMap(vimInstance).get(vimInstance.getVpcName());
      if (vpcId == null) {
        throw new VimDriverException("No such VPC " + vimInstance.getVpcName() + " exists");
      }
      Filter filter = new Filter();
      filter.setName("vpc-id");
      filter.setValues(Arrays.asList(vpcId));
      boolean done = false;
      List<BaseNetwork> nets = listNetworks(vimInstance);
      while (!done) {
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setFilters(Arrays.asList(filter));
        DescribeInstancesResult response = client.describeInstances(request);
        for (Reservation reservation : response.getReservations()) {
          for (Instance instance : reservation.getInstances()) {
            servers.add(Utils.getServer(instance, nets));
          }
        }
        request.setNextToken(response.getNextToken());
        if (response.getNextToken() == null) {
          done = true;
        }
      }
      return servers;
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @Override
  public Server rebuildServer(BaseVimInstance vimInstance, String serverId, String imageId)
      throws VimDriverException {
    return null;
  }

  @java.lang.Override
  public List<BaseNetwork> listNetworks(BaseVimInstance vimInstanceBase) throws VimDriverException {
    log.info("Listing networks");
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    List<BaseNetwork> nfvoNetworks = new ArrayList<>();
    AmazonEC2 client = createClient(vimInstance);
    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getVpcName());
    if (vpcId == null) {
      throw new VimDriverException("No such VPC " + vimInstance.getVpcName() + " exists");
    }
    Filter filter = new Filter();
    filter.setName("vpc-id");
    filter.setValues(Arrays.asList(vpcId));
    DescribeSubnetsRequest describeSubnetsRequest = new DescribeSubnetsRequest();
    describeSubnetsRequest.setFilters(Arrays.asList(filter));
    DescribeSubnetsResult subnetsResult = client.describeSubnets(describeSubnetsRequest);
    List<com.amazonaws.services.ec2.model.Subnet> subnets = subnetsResult.getSubnets();
    for (Subnet subnet : subnets) {
      nfvoNetworks.add((BaseNetwork) Utils.getNetworkFromSubnet(subnet));
    }
    return nfvoNetworks;
  }

  @java.lang.Override
  public java.util.List<DeploymentFlavour> listFlavors(BaseVimInstance vimInstanceBase)
      throws VimDriverException {
    List<DeploymentFlavour> flavours = new ArrayList<>();
    for (InstanceType type : InstanceType.values()) {
      DeploymentFlavour flavour = new DeploymentFlavour();
      flavour.setFlavour_key(type.toString());
      flavour.setExtId(type.toString());
      flavours.add(flavour);
    }
    return flavours;
  }

  @java.lang.Override
  public Server launchInstanceAndWait(
      BaseVimInstance vimInstance,
      String hostname,
      String image,
      String flavorExtId,
      String keyPair,
      java.util.Set<VNFDConnectionPoint> networks,
      java.util.Set<String> securityGroups,
      String userData,
      java.util.Map<String, String> floatingIps,
      java.util.Set<Key> keys)
      throws VimDriverException {

    Server server =
        launchInstance(
            vimInstance, hostname, image, flavorExtId, keyPair, networks, securityGroups, userData);

    return server;
  }

  @Override
  public Server launchInstanceAndWait(
      BaseVimInstance vimInstance,
      String hostname,
      String image,
      String extId,
      String keyPair,
      Set<VNFDConnectionPoint> networks,
      Set<String> securityGroups,
      String userdata)
      throws VimDriverException {
    return launchInstanceAndWait(
        vimInstance,
        hostname,
        image,
        extId,
        keyPair,
        networks,
        securityGroups,
        userdata,
        null,
        null);
  }

  @java.lang.Override
  public void deleteServerByIdAndWait(BaseVimInstance vimInstance, String id)
      throws VimDriverException {
    try {
      AmazonEC2 client = createClient((AmazonVimInstance) vimInstance);
      TerminateInstancesRequest req = new TerminateInstancesRequest().withInstanceIds(id);
      TerminateInstancesResult res = client.terminateInstances(req);
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @java.lang.Override
  public BaseNetwork createNetwork(BaseVimInstance vimInstanceBase, BaseNetwork network)
      throws VimDriverException {
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    AmazonEC2 client = createClient(vimInstance);
    try {
      String vpcId = getVpcsMap(vimInstance).get(vimInstance.getVpcName());
      if (vpcId == null) {
        throw new VimDriverException("No such VPC " + vimInstance.getVpcName() + " exists");
      }
      CreateSubnetResult res;
      log.debug("Generating CIDR");
      DescribeVpcsRequest req = new DescribeVpcsRequest();
      DescribeVpcsResult resVpc = client.describeVpcs(req);
      Vpc vpc = null;
      for (Vpc vpc1 : resVpc.getVpcs()) {
        if (vpc1.getVpcId().equals(vpcId)) {
          vpc = vpc1;
        }
      }
      if (vpc == null) {
        throw new VimDriverException("The vpc with id " + vpcId + " might not exist anymore");
      }
      String vpcCidr = vpc.getCidrBlock();
      String adrMask[] = vpcCidr.split("/");
      String adr[] = adrMask[0].split("…\\.")[0].split("\\.");
      Random random = new Random();
      int number = random.nextInt(255);
      String subnetCidr = adr[0] + "." + adr[1] + "." + number + "." + "0" + "/24";
      log.info("Generated CIDR " + subnetCidr);
      CreateSubnetRequest newReq =
          new CreateSubnetRequest().withVpcId(vpcId).withCidrBlock(subnetCidr);
      res = client.createSubnet(newReq);
      String id = res.getSubnet().getSubnetId();
      List<Tag> tags = new ArrayList<>();
      Tag tag = new Tag();
      tag.setKey("Name");
      tag.setValue(network.getName());
      tags.add(tag);
      CreateTagsRequest tagsRequest = new CreateTagsRequest().withTags(tags).withResources(id);
      client.createTags(tagsRequest);
      List<BaseNetwork> nets = listNetworks(vimInstanceBase);
      BaseNetwork returnNetwork = null;
      for (BaseNetwork net : nets) {
        if (net.getExtId().equals(res.getSubnet().getSubnetId())) {
          returnNetwork = net;
        }
      }

      return returnNetwork;
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  /**
   * Get the table of VPCs name to id by name
   *
   * @param vimInstance
   * @return
   * @throws VimDriverException
   */
  private HashMap<String, String> getVpcsMap(AmazonVimInstance vimInstance)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    try {
      DescribeVpcsRequest describeVpcsRequest = new DescribeVpcsRequest();
      DescribeVpcsResult describeVpcsResult = client.describeVpcs(describeVpcsRequest);
      HashMap<String, String> vpcNameId = new HashMap<>();
      for (Vpc vpc : describeVpcsResult.getVpcs()) {
        String id = vpc.getVpcId();
        String name = "";
        for (Tag tag : vpc.getTags()) {
          if (tag.getKey().equals("Name")) {
            name = tag.getValue();
          }
        }
        vpcNameId.put(name, id);
      }
      return vpcNameId;
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @java.lang.Override
  public DeploymentFlavour addFlavor(
      BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    return null;
  }

  @java.lang.Override
  public BaseNfvImage addImage(
      BaseVimInstance vimInstanceBase, BaseNfvImage imageBase, byte[] imageFile)
      throws VimDriverException {
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    AWSImage image = (AWSImage) imageBase;
    AmazonEC2 client = createClient(vimInstance);
    AWSImage newImage;
    Filter filter = new Filter();
    filter.setName("image-id");
    filter.setValues(Arrays.asList(image.getName()));
    DescribeImagesRequest describeImagesRequest = new DescribeImagesRequest();
    describeImagesRequest.setFilters(Arrays.asList(filter));
    DescribeImagesResult describeImagesResult = client.describeImages(describeImagesRequest);
    if (describeImagesResult.getImages().size() > 1) {
      throw new VimDriverException("There are several images with this name");
    }
    if (describeImagesResult.getImages().size() == 1) {
      newImage = Utils.getImage(describeImagesResult.getImages().get(0));
      return newImage;
    }
    filter.setName("name");
    filter.setValues(Arrays.asList(image.getName()));
    describeImagesRequest = new DescribeImagesRequest();
    describeImagesRequest.setFilters(Arrays.asList(filter));
    describeImagesResult = client.describeImages(describeImagesRequest);
    if (describeImagesResult.getImages().size() > 1) {
      throw new VimDriverException("There are several images with this id");
    }
    if (describeImagesResult.getImages().size() == 1) {
      newImage = Utils.getImage(describeImagesResult.getImages().get(0));
      return newImage;
    } else {
      throw new VimDriverException("Not possible to use the image " + image.getName());
    }
  }

  @java.lang.Override
  public BaseNfvImage addImage(BaseVimInstance vimInstance, BaseNfvImage image, String image_url)
      throws VimDriverException {
    return addImage(vimInstance, image, "".getBytes());
  }

  @java.lang.Override
  public BaseNfvImage updateImage(BaseVimInstance vimInstance, BaseNfvImage image)
      throws VimDriverException {
    return addImage(vimInstance, image, "".getBytes());
  }

  @java.lang.Override
  public BaseNfvImage copyImage(BaseVimInstance vimInstance, BaseNfvImage image, byte[] imageFile)
      throws VimDriverException {
    return null;
  }

  @java.lang.Override
  public boolean deleteImage(BaseVimInstance vimInstance, BaseNfvImage image)
      throws VimDriverException {
    return false;
  }

  @java.lang.Override
  public DeploymentFlavour updateFlavor(
      BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {

    return null;
  }

  @java.lang.Override
  public boolean deleteFlavor(BaseVimInstance vimInstance, String extId) throws VimDriverException {
    return false;
  }

  @Override
  public org.openbaton.catalogue.nfvo.networks.Subnet createSubnet(
      BaseVimInstance vimInstance,
      BaseNetwork createdNetwork,
      org.openbaton.catalogue.nfvo.networks.Subnet subnet)
      throws VimDriverException {
    return null;
  }

  /**
   * This is a stub that simply return the same network to avoid null pointer exceptions
   *
   * @param vimInstance vim
   * @param network network data
   * @return same network
   */
  @java.lang.Override
  public BaseNetwork updateNetwork(BaseVimInstance vimInstance, BaseNetwork network) {
    log.info("Called the update network method which is not implemented");
    return network;
  }

  @Override
  public org.openbaton.catalogue.nfvo.networks.Subnet updateSubnet(
      BaseVimInstance vimInstance,
      BaseNetwork updatedNetwork,
      org.openbaton.catalogue.nfvo.networks.Subnet subnet)
      throws VimDriverException {
    return null;
  }

  @Override
  public List<String> getSubnetsExtIds(BaseVimInstance vimInstance, String network_extId)
      throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteSubnet(BaseVimInstance vimInstance, String existingSubnetExtId)
      throws VimDriverException {
    return false;
  }

  @java.lang.Override
  public boolean deleteNetwork(BaseVimInstance vimInstanceBase, String extId)
      throws VimDriverException {
    try {
      AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
      AmazonEC2 client = createClient(vimInstance);
      DeleteSubnetRequest req = new DeleteSubnetRequest().withSubnetId(extId);
      DeleteSubnetResult res = client.deleteSubnet(req);
      return true;
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @java.lang.Override
  public BaseNetwork getNetworkById(BaseVimInstance vimInstanceBase, String id)
      throws VimDriverException {
    AmazonVimInstance vimInstance = (AmazonVimInstance) vimInstanceBase;
    AmazonEC2 client = createClient(vimInstance);
    try {
      Filter filter = new Filter();
      filter.setName("subnet-id");
      filter.setValues(Arrays.asList(id));
      DescribeSubnetsRequest req = new DescribeSubnetsRequest().withFilters(filter);
      DescribeSubnetsResult res = client.describeSubnets(req);
      if (res.getSubnets().size() < 1) {
        throw new VimDriverException("Network with id " + id + " does not exist");
      }
      return Utils.getNetworkFromSubnet(res.getSubnets().get(0));
    } catch (AmazonClientException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
  }

  @java.lang.Override
  public Quota getQuota(BaseVimInstance vimInstance) throws VimDriverException {
    log.info("Returning fake quota");
    Quota quota = new Quota();
    quota.setCores(99999);
    quota.setFloatingIps(444);
    quota.setInstances(20);
    quota.setRam(9999);
    return quota;
  }

  @java.lang.Override
  public String getType(BaseVimInstance vimInstance) throws VimDriverException {
    return "amazon";
  }
}
