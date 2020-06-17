#!/usr/local/bin/python3

"""
Fabric 2 script for executing commands on EC2 instances, and docker containers
@author Winston Nolan <winston.nolan@gmail.com>
"""
import json
import os
import sys
import boto3
import requests
from boto3 import exceptions
from fabric import *
from sshconf import empty_ssh_config, read_ssh_config
from termcolor import colored as c

# vars
# environments
environments = ['stg', 'prd']
# user
user_dir = os.environ['HOME']
ssh_config = os.environ['FABRIC_SSH_CONFIG_FILE']
ssh_config_file_path = f"{user_dir}/{ssh_config}"
company = os.environ['FABRIC_COMPANY']
# log
prefix = 'Info: '
# colors
grey = 'grey'
red = 'red'
green = 'green'
yellow = 'yellow'
blue = 'blue'
magenta = 'magenta'
cyan = 'cyan'
white = 'white'


def get_hosts_from_ec2(environment, filter):
    """
    Create hosts pool, containing available hosts to be targeted
    """
    if environment not in environments:
        raise Exception(f"Environment must be one of {environments}")

    # get ip information
    get_local_ip_information()

    # print info
    print(f"Targeting environment [{c(environment, white, attrs=['bold'])}] with filter '{c(filter, white, attrs=['bold'])}'")

    boto3.setup_default_session(profile_name=f"{company}-{environment}")
    ec2 = boto3.resource('ec2')

    # setup filters
    filters = [
        {'Name': 'instance-state-name', 'Values': ['running']},  # only get running instances
        {'Name': 'tag:Name', 'Values': ['*{query}*'.format(query=filter)]},
    ]

    # make api call to EC2
    instances = ec2.instances.filter(Filters=filters)
    return instances


def extract_instances_information(context, environment, filter, tags=None):
    """
    Get information from instances and create hosts pool
    """
    default_attributes = [
        'Name',
        'private_ip_address',
        'public_ip_address',
        'instance_type'
    ]
    attributes = default_attributes if tags is None else tags.split(',')

    # get instances with filter
    instances = get_hosts_from_ec2(environment, filter)

    instance_name = None
    if len(attributes) is 1:
        results = []
    else:
        results = {}

    for instance in instances:
        # gather data from tags
        for tag in instance.tags:
            # set other attributes
            if tag['Key'] in attributes:
                if tag['Key'] == 'Name':
                    instance_name=tag['Value']
                    instance_id=getattr(instance, 'id')
                    instance_name = f'{instance_name}[{instance_id}]'

                # print(tag['Value'])
                results.update({instance_name: {tag['Key']: tag['Value']}})

        # gather data from attributes
        # figure out what properties the instance object has
        # print(instance.__dict__.keys())
        instance_properties = [i for i in dir(instance) if not callable(i)]
        # print(instance_properties)
        for attribute in attributes:
            if attribute in instance_properties:
                if isinstance(results, list):
                    results.append(getattr(instance, attribute))
                else:
                    results[instance_name].update({attribute: getattr(instance, attribute)})

    # print hosts information
    print(f"Information for attributes: {c(attributes, white, attrs=['bold'])}")
    number_of_hosts = len(results)
    print(c(f"Found {number_of_hosts} host(s)", white, attrs=['bold']))
    print(json.dumps(results, sort_keys=True, indent=4))

    return results


def setup_host_group(context, environment, filter, tags='private_ip_address'):
    """
    Setup hosts group from EC2 instances using boto3
    """
    hosts = extract_instances_information(context, environment, filter, tags)

    if len(hosts) == 0:
        exit("No hosts found - refusing to continue")

    config = get_config()
    connection = [Connection(host=host, config=config) for host in hosts]

    return connection


def get_local_ip_information():
    """
    Get local IP Address
    """
    print(c("---", cyan))
    print(c("Your current IP Address is: ", white, attrs=['bold']))
    os.system("wget -O - -q icanhazip.com")
    print(c("---", cyan))


@task
def set_ssh_config(context, environment, filter='SSH Bastion', tags='public_ip_address'):
    """
    Set Ip Address of Bastion in ssh config file
    """
    hosts = extract_instances_information(context, environment, filter, tags)

    if len(hosts) == 0:
        exit("No hosts found - refusing to continue")

    config = read_ssh_config(ssh_config_file_path)
    ssh_config_hostname = f"bastion.{environment}.{company}"
    # set values and write
    config.set(ssh_config_hostname, Hostname=f"{hosts[0]}")
    config.write(ssh_config_file_path)


def get_config():
    """
    Set correct config for connections
    """
    config = Config(
        runtime_ssh_path=ssh_config_file_path,
        # overrides={
        #     'sudo': {
        #         'user': 'www'
        #     }
        # }
    )
    return config


@task
def get_hosts_info(context, environment, filter, tags=None):
    """
    Get information about hosts
    :param environment: The environment to target (Staging, Development, Production)
    :param filter: The filter wildcard string to run the commands 
    :param tags: Tags to get information from - see https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#instance
    """
    if environment not in environments:
        raise Exception("Tags cannot be empty for this method")
    # get hosts info
    extract_instances_information(context, environment, filter, tags)


@task
def ip(context):
    """
    Get local ip address
    You will need to add this to your firewall rule to be able to access your network
    """
    get_local_ip_information()


@task
def report(context, environment, filter):
    """
    Hosts report their status
    :param environment: The environment to target (Staging, Development, Production)
    :param filter: The filter wildcard string to run the commands 
    """
    connection = setup_host_group(context, environment, filter)
    group = ThreadingGroup.from_connections(connection)
    
    try:
        results = group.run('uname -a; uptime; df -h;')
    except exceptions.GroupException as e:
        results = e.result
        pass

    # results
    print_results(results)


@task
def exec(context, environment, filter, command):
    """
    Execute command on systems
    :param environment: The environment to target (Staging, Development, Production)
    :param filter: The filter wildcard string to run the commands on some hosts
    :param command: The command to execute
    """
    connection = setup_host_group(context, environment, filter)
    group = ThreadingGroup.from_connections(connection)

    try:
        results = group.run(command, hide=True)
    except exceptions.GroupException as e:
        results = e.result
        pass

    # results
    print_results(results)


@task
def exec_docker(context, environment, filter, command, docker='php', user='www'):
    """
    Execute command on a docker container running on the systems
    :param environment: The environment to target (Staging, Development, Production)
    :param filter: The filter wildcard string to run the commands on some hosts
    :param command: The command to execute
    :param docker: The docker container to target
    :param user: The user inside the docker targeted container
    """
    connection = setup_host_group(context, environment, filter)
    group = ThreadingGroup.from_connections(connection)

    sudo_system_user = 'sudo -u www'
    docker_container_name = get_docker_container_name(docker)
    docker_command = f"{sudo_system_user} docker exec -itu {user} {docker_container_name} bash -c '{command}'"

    print(f"{c(prefix, white, attrs=['bold'])}Running command on the [{docker}] docker sub-system")
    print(f"{c('Docker command:', white, attrs=['bold'])} {docker_command}")

    try:
        results = group.run(docker_command, pty=True, hide=True)
    except exceptions.GroupException as e:
        results = e.result
        pass

    # results
    print_results(results)


@task
def exec_magento(context, environment, filter, command='bin/magento', docker='php', user='www'):
    """
    Execute magento on the php docker container running on the systems
    :param environment: The environment to target (Staging, Development, Production)
    :param filter: The filter wildcard string to run the commands on some hosts
    :param command: The command to execute
    :param docker: The docker container to target
    :param user: The user inside the docker targeted container
    """
    connection = setup_host_group(context, environment, filter)
    group = ThreadingGroup.from_connections(connection)

    bin_magento = 'bin/magento'
    if bin_magento not in command:
        command = f"{bin_magento} {command}"

    sudo_user = 'sudo -u www'
    docker_container_name = get_docker_container_name(docker)
    docker_command = f"{sudo_user} docker exec -itu {user} {docker_container_name} bash -c 'cd /var/www/current/src; {command}'"

    print(f"{c(prefix, white, attrs=['bold'])}Running command on the [{docker}] docker sub-system")
    print(f"{c('Docker command:', white, attrs=['bold'])} {docker_command}")
    
    try:
        results = group.run(docker_command, pty=True, hide=True)
    except exceptions.GroupException as e:
        results = e.result
        pass

    # results
    print_results(results)


def print_results(results):
    """
    Print out results of group operations
    """
    for r in results:
        connection = results[r]
        print(c("---", yellow, attrs=['bold']))
        print(f"{c(r.host, white, attrs=['bold'])}")
        print(c("---", yellow, attrs=['bold']))
        print(results[r])


def get_docker_container_name(key):
    """
    Return docker container name by key
    """
    containers = {
        "php": f"{company}_php-fpm_1",
        "nginx": f"{company}_nginx_1",
        "postfix": f"{company}_postfix_1",
        "logrotate": f"{company}_logrotate_1",
        "varnish": f"{company}_varnish_1"
    }

    return containers[key]
