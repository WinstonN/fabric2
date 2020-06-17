# fabric2
fabric2 is the upgrade from fabric1

## why use fabric2?

The whole purpose of fabric, is to allow you to perform tasks on infrastructure.
Running commands, inside of ec2 instances (including magento2 deployments)
Running commands inside docker containers
Running magento2 bin commands

All of the above, across multiple instances, via instance discovery, all, in parallel

fabric is great for the following reasons
* written in python
* supports python3
* zero setup on your ec2 instances
* communication through SSH (supports user SSH config files - see examples)
* zero setup on the instances
* with boto3 fabric can do much much more than just issue SSH commands
* extremely flexible

## Install fabric2
Clone repo, then run
```pip3 install -r requirements.txt```

## setup
#### AWS Profiles

I use a aws credentials file for my projects
and example should look like the below. The company name here is important
because we will be using it in our variables.env file (and finally in our fabfile.py)

```bash
❯❯❯ cat ~/.aws/credentials

[default]
region=eu-west-1

[company-stg]
region=REGION
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET

[company-prd]
region=REGION
aws_access_key_id=ACCESS_KEY
aws_secret_access_key=SECRET
```

#### SSH config
I use ssh config files, for all my projects

Inside of my ~/.ssh/config file I have the following
```bash
❯❯❯ cat ~/.ssh/config

Include ~/.ssh/config.d/git
Include ~/.ssh/config.d/company1
Include ~/.ssh/config.d/company2
Include ~/.ssh/config.d/company3

# All hosts
Host *
  # Never ever do ForwardAgent to unknown hosts
  # https://blog.filippo.io/ssh-whoami-filippo-io/
  ForwardAgent no
  # Roaming through the OpenSSH client: CVE-2016-0777 and CVE-2016-0778
  UseRoaming no
  AddKeysToAgent yes
  # Might need to remove this
  IdentitiesOnly yes
```
An example of the ~/.ssh/config.d/company1 looks like
```bash
❯❯❯ cat ~/.ssh/config.d/company1

# Company1
# Keys
# Production
Host bastion.prd.company1
  HostName 1.1.1.1
  IdentityFile ~/.ssh/company1-prd-key.pem
  User USER
  ForwardAgent yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null

# Staging
Host bastion.stg.company1
  HostName 2.2.2.2
  IdentityFile ~/.ssh/company1-stg-key.pem
  User USER
  ForwardAgent yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null

# Proxy Commands
# Production
Host 10.1.*.*
  ProxyCommand ssh -e none %r@bastion.prd.company1 -W %h:%p
  ForwardAgent yes
  User USER
  IdentityFile ~/.ssh/company1-prd-key.pem
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null

# Staging
Host 10.2.*.*
  ProxyCommand ssh -e none %r@bastion.stg.company1 -W %h:%p
  ForwardAgent yes
  User USER
  IdentityFile ~/.ssh/company1-stg-key.pem
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null%
```

#### Working with fabric
When you issue ``fab`` you'll see the following
```bash
❯❯❯ fab
Usage: fab [--core-opts] task1 [--task1-opts] ... taskN [--taskN-opts]

Core options:

  --complete                         Print tab-completion candidates for given parse remainder.
  --hide=STRING                      Set default value of run()'s 'hide' kwarg.
  --no-dedupe                        Disable task deduplication.
  --print-completion-script=STRING   Print the tab-completion script for your preferred shell (bash|zsh|fish).
  --prompt-for-login-password        Request an upfront SSH-auth password prompt.
  --prompt-for-passphrase            Request an upfront SSH key passphrase prompt.
  --prompt-for-sudo-password         Prompt user at start of session for the sudo.password config value.
  --write-pyc                        Enable creation of .pyc files.
  -c STRING, --collection=STRING     Specify collection name to load.
  -d, --debug                        Enable debug output.
  -D INT, --list-depth=INT           When listing tasks, only show the first INT levels.
  -e, --echo                         Echo executed commands before running.
  -f STRING, --config=STRING         Runtime configuration file to use.
  -F STRING, --list-format=STRING    Change the display format used when listing tasks. Should be one of: flat (default), nested, json.
  -h [STRING], --help[=STRING]       Show core or per-task help and exit.
  -H STRING, --hosts=STRING          Comma-separated host name(s) to execute tasks against.
  -i, --identity                     Path to runtime SSH identity (key) file. May be given multiple times.
  -l [STRING], --list[=STRING]       List available tasks, optionally limited to a namespace.
  -p, --pty                          Use a pty when executing shell commands.
  -r STRING, --search-root=STRING    Change root directory used for finding task modules.
  -R, --dry                          Echo commands instead of running.
  -S STRING, --ssh-config=STRING     Path to runtime SSH config file.
  -t INT, --connect-timeout=INT      Specifies default connection timeout, in seconds.
  -T INT, --command-timeout=INT      Specify a global command execution timeout, in seconds.
  -V, --version                      Show version and exit.
  -w, --warn-only                    Warn, instead of failing, when shell commands fail.
```
and ``fab -l`` to list commands
```bash
❯❯❯ fab -l

Available tasks:

  exec             Execute command on systems
  exec-docker      Execute command on a docker container running on the systems
  exec-magento     Execute magento on the php docker container running on the systems
  get-hosts-info   Get information about hosts
  ip               Get local ip address
  report           Hosts report their status
  set-ssh-config   Set Ip Address of Bastion in ssh config file
```
## Example commands
```bash
# get instances and their info 
# -f is for filter (ec2 instances filter in the console, works with wildcards)
fab get-hosts-info -f "abc*" -e environment # stg | prd

# execute a command on a system
fab exec -e environment -f "abc*Cron-host" -c "sudo -u root service crond status"

# creating magento users
# NOTE: This command has been built to issue inside of a php docker container
fab exec-magento -f "abc*Admin-host" -e environment -c "admin:user:create --admin-user='pica.chu' --admin-password='picachu!' --admin-email='pica.chu@pica.com' --admin-firstname='Pica' --admin-lastname='Chu'"

```