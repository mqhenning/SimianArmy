/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
package com.netflix.simianarmy.aws.conformity.rule;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.ec2.model.GroupIdentifier;
import com.amazonaws.services.ec2.model.Instance;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.netflix.simianarmy.client.aws.AWSClient;
import com.netflix.simianarmy.conformity.AutoScalingGroup;
import com.netflix.simianarmy.conformity.Cluster;
import com.netflix.simianarmy.conformity.Conformity;
import com.netflix.simianarmy.conformity.ConformityRule;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * The class implementing a conformity rule that checks whether or not all instances have a certain tag.
 */
public class InstanceHasTags implements ConformityRule {
    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceHasStatusUrl.class);

    private static final String RULE_NAME = "InstanceHasTag";
    private final String reason;

    /**
     * We probably need something else like "allowed tag values" but right now this only 
     * has something like these Tags are there or not
     *
     * private final Collection<String> requiredSecurityGroupNames = Sets.newHashSet();
     *
     */
    private final Collection<String> requiredTags = Sets.newHashSet();

    private AWSCredentialsProvider awsCredentialsProvider;

    /**
     * Constructor.
     * @param requiredTags
     *      The tags that are required to have for every instance of an ASG (or region).
     */
    public InstanceHasTags(String... requiredTags) {
        this(new DefaultAWSCredentialsProviderChain(), requiredTags);
    }

    /**
     * Constructor.
     * @param awsCredentialsProvider
     *      The AWS credentials provider
     * @param requiredTags
     *      The tags that are required to have for every instance of an ASG (or region).
     */
    public InstanceHasTags(AWSCredentialsProvider awsCredentialsProvider, String... requiredTags)
    {
        this.awsCredentialsProvider = awsCredentialsProvider;
        Validate.notNull(requiredTags);
        for (String tagName : requiredTags) {
            Validate.notNull(tagName);
            this.requiredTags.add(tagName.trim());
        }
        this.reason = String.format("Instances do not have tags (%s)",
		StringUtils.join(this.requiredTags, ","));
    }

    @Override
    public Conformity check(Cluster cluster) {
        List<String> instanceIds = Lists.newArrayList();
        for (AutoScalingGroup asg : cluster.getAutoScalingGroups()) {
            instanceIds.addAll(asg.getInstances());
        }
        Collection<String> failedComponents = Lists.newArrayList();
        if (instanceIds.size() != 0) {
            Map<String, List<String>> instanceIdToTags = getInstanceTags(
                    cluster.getRegion(), instanceIds.toArray(new String[instanceIds.size()]));

            for (Map.Entry<String, List<String>> entry : instanceIdToTags.entrySet()) {
                String instanceId = entry.getKey();
                if (!checkTags(entry.getValue())) {
                    LOGGER.info(String.format("Instance %s does not have all tags", instanceId));
                    failedComponents.add(instanceId);
                }
            }
        }
        return new Conformity(getName(), failedComponents);
    }

    @Override
    public String getName() {
        return RULE_NAME;
    }

    @Override
    public String getNonconformingReason() {
        return reason;
    }

    /**
     * Checks whether the collection of tag keys are valid. The default implementation here is to check
     * whether the tags contain the required tags. The method can be overridden for different
     * rules.
     * @param TagNames
     *      The collection of security group names
     * @return
     *      true if the tag names are valid, false otherwise.
     */
    protected boolean checkTags(Collection<String> TagNames) {
        for (String requiredTag : requiredTags) {
            if (!TagNames.contains(requiredTags)) {
                LOGGER.info(String.format("Required tag %s is not found.", requiredTag));
                return false;
            }
        }
        return true;
    }

    /**
     * Gets the tag keys for a list of instance ids of the same region. The default implementation
     * is using an AWS client. The method can be overridden in subclasses to get the tags differently.
     * @param region
     *      the region of the instances
     * @param instanceIds
     *      the instance ids, all instances should be in the same region.
     * @return
     *      the map from instance id to the list of tag keys the instance has
     */
    protected Map<String, List<String>> getInstanceTags(String region, String... instanceIds) {
        Map<String, List<String>> result = Maps.newHashMap();
        if (instanceIds == null || instanceIds.length == 0) {
            return result;
        }
        AWSClient awsClient = new AWSClient(region, awsCredentialsProvider);
        for (Instance instance : awsClient.describeInstances(instanceIds)) {
            // Ignore instances that are in VPC
            if (StringUtils.isNotEmpty(instance.getVpcId())) {
                LOGGER.info(String.format("Instance %s is in VPC and is ignored.", instance.getInstanceId()));
                continue;
            }

            if (!"running".equals(instance.getState().getName())) {
                LOGGER.info(String.format("Instance %s is not running, state is %s.",
                        instance.getInstanceId(), instance.getState().getName()));
                continue;
            }

            List<Tag> tags = Lists.newArrayList();
            for (Tag instanceTag : instance.getTags()) {
                tags.add(instanceTag.getKey());
            }

            result.put(instance.getInstanceId(), tags);
        }
        return result;
    }
}
