#!/usr/bin/env python3

# Authors:
#    Description: Chad Schmutzer (schmutze@amazon.com)
#  License:
#    Description: 'Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
#      Licensed under the Amazon Software License (the "License"). You may not use this file
#      except in compliance with the License. A copy of the License is located at
#
#      http://aws.amazon.com/asl/
#
#      or in the "license" file accompanying this file. This file is distributed on an "AS IS"
#      BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#      License for the specific language governing permissions and limitations under the License.'

import boto3

imageId = 'ami-08d658f84a6d84a80'
minTargetCapacity = 3
subnetTimo = 'subnet-f11d50b9'
subnet1a = 'subnet-0fc4d2543f3dcc255'
subnet1b = 'subnet-09b9d0dbca4bae8a5'
subnet1c = 'subnet-0437dfe009676c434'

client = boto3.client('ec2')

# create the launch template
try:
  response = client.create_launch_template(
    LaunchTemplateName = 'myLaunchTemplate',
    VersionDescription = 'My launch template for Spot Blocks with subnet 1a',
    LaunchTemplateData = {
      'ImageId': imageId,
      'TagSpecifications': [
        {
          'ResourceType': 'instance',
          'Tags': [
            {
              'Key': 'Name',
              'Value': 'myClusterInstance'
            }
          ]
        }
      ]        
    }
  )
  print(response)
except:
  print("Error creating launch template (perhaps it already exists). Skipping create.")

# make EC2 Fleet request
try:
  response = client.create_fleet(
    SpotOptions = {
      'AllocationStrategy': 'lowestPrice',
      'InstanceInterruptionBehavior': 'terminate',
      'SingleInstanceType': True,
      'SingleAvailabilityZone': True,
      'MinTargetCapacity': minTargetCapacity
    },
    LaunchTemplateConfigs = [
      {
        'LaunchTemplateSpecification': {
          'LaunchTemplateName': 'myLaunchTemplate',
          'Version': '1'
        },
        'Overrides': [
          {
            'InstanceType': 't2.micro',
            'SubnetId': subnetTimo          
          },
        ]
      }
    ],
    TargetCapacitySpecification = {
      'TotalTargetCapacity': minTargetCapacity,
      'DefaultTargetCapacityType': 'spot'
    },
    #Type='instant'
    Type='maintain'
  )
  print(response)
except Exception as e:
  print("Error creating EC2 Fleet: {}".format(e))