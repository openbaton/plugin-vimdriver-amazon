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
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base64;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.*;
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
  private AmazonEC2 createClient(VimInstance vimInstance) throws VimDriverException {
    BasicAWSCredentials awsCreds =
        new BasicAWSCredentials(vimInstance.getUsername(), vimInstance.getPassword());
    Regions regions;
    AmazonEC2 client;
    try {
      regions = Regions.fromName(vimInstance.getLocation().getName());
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
      VimInstance vimInstance,
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
      String changeUserData = changeHostname(userData, name);
      log.info(changeUserData);
      AmazonEC2 client = createClient(vimInstance);
      Gson gson = new Gson();
      String oldVNFDCP = gson.toJson(networks);
      Set<VNFDConnectionPoint> newNetworks =
          gson.fromJson(oldVNFDCP, new TypeToken<Set<VNFDConnectionPoint>>() {}.getType());
      RunInstancesRequest runInstancesRequest = new RunInstancesRequest();
      String vpcId = getVpcsMap(vimInstance).get(vimInstance.getTenant());
      if (vpcId == null) {
        throw new VimDriverException("No such VPC " + vimInstance.getTenant() + " exists");
      }
      log.info("Found the VPC ID: " + vpcId);
      byte[] encodedData = Base64.encodeBase64(changeUserData.getBytes());
      DescribeVpcsRequest describeVpcsRequest = new DescribeVpcsRequest();
      DescribeVpcsResult describeVpcsResult = client.describeVpcs(describeVpcsRequest);
      List<DeploymentFlavour> flavours = listFlavors(vimInstance);
      log.info("Listed flavours");
      List<Network> presentSubnets = listNetworks(vimInstance);
      log.info("Listed subents");
      Collection<InstanceNetworkInterfaceSpecification> inters = new ArrayList<>();
      Set<String> groupIds = getSecurityIdFromName(secGroup, client, vimInstance);
      log.info("Retrieved security ids");
      int deviceIndex = 0;
      for (Network net : searchForRelevantSubnets(presentSubnets, newNetworks)) {
        inters.add(createInterface(net, deviceIndex, newNetworks));
        deviceIndex++;
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
      ModifyInstanceAttributeRequest groupsReq =
          new ModifyInstanceAttributeRequest().withGroups(groupIds).withInstanceId(id);
      log.info("Assigning security groups to instance " + id);
      ModifyInstanceAttributeResult groupRes = client.modifyInstanceAttribute(groupsReq);
      List<Server> servers = listServer(vimInstance);
      for (Server ser : servers) {
        if (ser.getHostName().equals(name)) {
          server = ser;
        }
      }

    } catch (VimException e) {
      log.error(e.getMessage(), e);
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    } catch (UnsupportedEncodingException e) {
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      throw vimDriverException;
    }
    log.info("Instance " + name + " launched");
    return server;
  }

  /**
   * Checks if the image exists inside AWS and returns its ID
   *
   * @param nameId Either name or the id of the image inside AWS
   * @param client AmazonEC2 client to make a request
   * @return id of the image or null if no image is there
   */
  private String imageExistsOnAWS(String nameId, AmazonEC2 client) {
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
   * Creates an interface for the instance in order to connect to subnet. Cross checks for floating
   * ips and enables it if necessary. Currently supports only random floating ips.
   *
   * @param net subnet inside AWS represented through NFVO network
   * @param deviceIndex device index for the interface is required by AWS
   * @param cps VNFD connection points
   * @return the list of interfaces
   */
  private InstanceNetworkInterfaceSpecification createInterface(
      Network net, int deviceIndex, Set<VNFDConnectionPoint> cps) {
    InstanceNetworkInterfaceSpecification interSpec =
        new InstanceNetworkInterfaceSpecification()
            .withDeleteOnTermination(true)
            .withSubnetId(net.getExtId())
            .withDeviceIndex(deviceIndex);
    String floatingIp = "";
    for (VNFDConnectionPoint cp : cps) {
      if (net.getName().equals(cp.getVirtual_link_reference())) {
        floatingIp = cp.getFloatingIp();
      }
    }
    if (floatingIp != null) {
      interSpec.setAssociatePublicIpAddress(true);
    }
    return interSpec;
  }

  /**
   * Crosscheck the connection points with subnets and return the relevant ones
   *
   * @param nets All subnets
   * @param cps All connection points
   * @return subnets the instance is connected to
   */
  private List<Network> searchForRelevantSubnets(List<Network> nets, Set<VNFDConnectionPoint> cps) {
    List<Network> relevantSubnets = new ArrayList<>();
    for (VNFDConnectionPoint cp : cps) {
      for (Network net : nets) {
        if (net.getName().equals(cp.getVirtual_link_reference())) {
          relevantSubnets.add(net);
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
   * @param vimInstance vim description
   * @return list of the security groups ids
   * @throws VimDriverException in case there is no VPC with such name or one of the security groups
   *     does not exits
   */
  private Set<String> getSecurityIdFromName(
      Set<String> groupNames, AmazonEC2 client, VimInstance vimInstance) throws VimDriverException {
    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getTenant());
    if (vpcId == null) {
      throw new VimDriverException("No such VPC " + vimInstance.getTenant() + " exists");
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
            "No group " + name + "exists on VPC " + vimInstance.getTenant());
      }
    }

    return groupIds;
  }

  @java.lang.Override
  public java.util.List<NFVImage> listImages(VimInstance vimInstance) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
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
    List<NFVImage> images = new ArrayList<>();
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
  }

  @java.lang.Override
  public java.util.List<Server> listServer(VimInstance vimInstance) throws VimDriverException {
    List<Server> servers = new ArrayList<>();
    AmazonEC2 client = createClient(vimInstance);
    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getTenant());
    if (vpcId == null) {
      throw new VimDriverException("No such VPC " + vimInstance.getTenant() + " exists");
    }
    Filter filter = new Filter();
    filter.setName("vpc-id");
    filter.setValues(Arrays.asList(vpcId));
    boolean done = false;
    List<Network> nets = listNetworks(vimInstance);
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
  }

  @java.lang.Override
  public java.util.List<Network> listNetworks(VimInstance vimInstance) throws VimDriverException {
    List<Network> nfvoNetworks = new ArrayList<>();
    AmazonEC2 client = createClient(vimInstance);
    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getTenant());
    if (vpcId == null) {
      throw new VimDriverException("No such VPC " + vimInstance.getTenant() + " exists");
    }
    Filter filter = new Filter();
    filter.setName("vpc-id");
    filter.setValues(Arrays.asList(vpcId));
    DescribeSubnetsRequest describeSubnetsRequest = new DescribeSubnetsRequest();
    describeSubnetsRequest.setFilters(Arrays.asList(filter));
    DescribeSubnetsResult subnetsResult = client.describeSubnets(describeSubnetsRequest);
    List<com.amazonaws.services.ec2.model.Subnet> subnets = subnetsResult.getSubnets();
    for (Subnet subnet : subnets) {
      nfvoNetworks.add(Utils.getNetworkFromSubnet(subnet));
    }
    return nfvoNetworks;
  }

  @java.lang.Override
  public java.util.List<DeploymentFlavour> listFlavors(VimInstance vimInstance)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
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
      VimInstance vimInstance,
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
    AmazonEC2 client = createClient(vimInstance);

    Server server =
        launchInstance(
            vimInstance, hostname, image, flavorExtId, keyPair, networks, securityGroups, userData);

    return server;
  }

  @Override
  public Server launchInstanceAndWait(
      VimInstance vimInstance,
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
  public void deleteServerByIdAndWait(VimInstance vimInstance, String id)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    TerminateInstancesRequest req = new TerminateInstancesRequest().withInstanceIds(id);
    TerminateInstancesResult res = client.terminateInstances(req);
  }

  @java.lang.Override
  public Network createNetwork(VimInstance vimInstance, Network network) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);

    String vpcId = getVpcsMap(vimInstance).get(vimInstance.getTenant());
    if (vpcId == null) {
      throw new VimDriverException("No such VPC " + vimInstance.getTenant() + " exists");
    }
    CreateSubnetResult res;
    try {
      CreateSubnetRequest req =
          new CreateSubnetRequest()
              .withVpcId(vpcId)
              .withCidrBlock(network.getSubnets().iterator().next().getCidr());
      res = client.createSubnet(req);
    } catch (Exception e) {
      log.debug("Provided CIDR is invalid, generating different one");
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
    }
    String id = res.getSubnet().getSubnetId();
    List<Tag> tags = new ArrayList<>();
    Tag tag = new Tag();
    tag.setKey("Name");
    tag.setValue(network.getName());
    tags.add(tag);
    CreateTagsRequest tagsRequest = new CreateTagsRequest().withTags(tags).withResources(id);
    client.createTags(tagsRequest);
    List<Network> nets = listNetworks(vimInstance);
    Network returnNetwork = null;
    for (Network net : nets) {
      if (net.getExtId().equals(res.getSubnet().getSubnetId())) {
        returnNetwork = net;
      }
    }

    return returnNetwork;
  }

  private HashMap<String, String> getVpcsMap(VimInstance vimInstance) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
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
  }

  @java.lang.Override
  public DeploymentFlavour addFlavor(VimInstance vimInstance, DeploymentFlavour deploymentFlavour)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    return null;
  }

  @java.lang.Override
  public NFVImage addImage(VimInstance vimInstance, NFVImage image, byte[] imageFile)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    NFVImage newImage;
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
  public NFVImage addImage(VimInstance vimInstance, NFVImage image, String image_url)
      throws VimDriverException {
    return addImage(vimInstance, image, "".getBytes());
  }

  @java.lang.Override
  public NFVImage updateImage(VimInstance vimInstance, NFVImage image) throws VimDriverException {
    return addImage(vimInstance, image, "".getBytes());
  }

  @java.lang.Override
  public NFVImage copyImage(VimInstance vimInstance, NFVImage image, byte[] imageFile)
      throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    return null;
  }

  @java.lang.Override
  public boolean deleteImage(VimInstance vimInstance, NFVImage image) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    return false;
  }

  @java.lang.Override
  public DeploymentFlavour updateFlavor(
      VimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    return null;
  }

  @java.lang.Override
  public boolean deleteFlavor(VimInstance vimInstance, String extId) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    return false;
  }

  /**
   * This
   *
   * @param vimInstance
   * @param createdNetwork
   * @param subnet
   * @return
   * @throws VimDriverException
   */
  @java.lang.Override
  public org.openbaton.catalogue.nfvo.Subnet createSubnet(
      VimInstance vimInstance, Network createdNetwork, org.openbaton.catalogue.nfvo.Subnet subnet)
      throws VimDriverException {
    log.info("Creating subnet " + subnet.getName() + " on by return the subnet:");
    log.info(createdNetwork.toString());
    org.openbaton.catalogue.nfvo.Subnet sub = new org.openbaton.catalogue.nfvo.Subnet();
    sub.setName(createdNetwork.getName() + "_subnet");
    sub.setExtId(createdNetwork.getExtId());
    sub.setCidr(createdNetwork.getSubnets().iterator().next().getCidr());
    sub.setNetworkId(createdNetwork.getExtId());
    return sub;
  }

  /**
   * This is a stub that simply return the same network to avoid null pointer exceptions
   *
   * @param vimInstance vim
   * @param network network data
   * @return same network
   */
  @java.lang.Override
  public Network updateNetwork(VimInstance vimInstance, Network network) {
    log.info("Called the update network method which is not implemented");
    return network;
  }

  /**
   * This is a stub that simply return the same network to avoid null pointer exceptions
   *
   * @param vimInstance vim
   * @param subnet network data
   * @return same network
   */
  @java.lang.Override
  public org.openbaton.catalogue.nfvo.Subnet updateSubnet(
      VimInstance vimInstance, Network updatedNetwork, org.openbaton.catalogue.nfvo.Subnet subnet) {
    log.info("Called the update subnet method which is not implemented");
    return subnet;
  }

  @java.lang.Override
  public java.util.List<String> getSubnetsExtIds(VimInstance vimInstance, String network_extId)
      throws VimDriverException {
    List<Network> nets = listNetworks(vimInstance);
    List<String> ids = new ArrayList<>();
    for (Network net : nets) {
      ids.add(net.getExtId());
    }
    return ids;
  }

  @java.lang.Override
  public boolean deleteSubnet(VimInstance vimInstance, String existingSubnetExtId)
      throws VimDriverException {
    return true;
  }

  @java.lang.Override
  public boolean deleteNetwork(VimInstance vimInstance, String extId) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    DeleteSubnetRequest req = new DeleteSubnetRequest().withSubnetId(extId);
    DeleteSubnetResult res = client.deleteSubnet(req);
    return true;
  }

  @java.lang.Override
  public Network getNetworkById(VimInstance vimInstance, String id) throws VimDriverException {
    AmazonEC2 client = createClient(vimInstance);
    Filter filter = new Filter();
    filter.setName("subnet-id");
    filter.setValues(Arrays.asList(id));
    DescribeSubnetsRequest req = new DescribeSubnetsRequest().withFilters(filter);
    DescribeSubnetsResult res = client.describeSubnets(req);
    if (res.getSubnets().size() < 1) {
      throw new VimDriverException("Network with id " + id + " does not exist");
    }
    return Utils.getNetworkFromSubnet(res.getSubnets().get(0));
  }

  @java.lang.Override
  public Quota getQuota(VimInstance vimInstance) throws VimDriverException {
    log.info("Returning fake quota");
    Quota quota = new Quota();
    quota.setCores(99999);
    quota.setFloatingIps(444);
    quota.setInstances(20 - listServer(vimInstance).size());
    quota.setRam(9999);
    return quota;
  }

  @java.lang.Override
  public String getType(VimInstance vimInstance) throws VimDriverException {
    return "amazon";
  }
}
