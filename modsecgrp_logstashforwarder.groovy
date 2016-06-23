import groovy.json.JsonSlurper

/************
usage:
   vi modsecgrp.groovy
   ~/.sdkman/candidates/groovy/2.4.6/bin/groovyc modsecgrp.groovy
   java -cp .:./groovy-2.4.7.jar:./groovy-json-2.4.7.jar modsecgrp
************/

def getSecurityGroupID(keyvalue) {
 def awscmd = 'aws ec2 describe-security-groups --region us-east-1'
 def awscmdtext = awscmd.execute().text
 def slurper = new JsonSlurper()
 def result = slurper.parseText(awscmdtext)
 def keynames = result.SecurityGroups.GroupName
 def keyclosure = { it =~ keyvalue }
 def count = keynames.grep(keyclosure).size()
 if (count == 0) {
  println "GroupName '$keyvalue' not found. exiting with rc=-1"
  System.exit(-1)
 }
 if (count > 1) {
  println "GroupName '$keyvalue' too common. exiting with rc=-1"
  println keynames.grep(keyclosure)
  System.exit(-1)
 }
 def ixkeyname = keynames.findIndexOf(keyclosure)
 result.SecurityGroups.GroupId[ixkeyname]
}

def getInstanceIPAddresses(keyvalue) {
 def awscmd = 'aws ec2 describe-instances --region us-east-1' +
              ' --filters Name=instance-state-name,Values=running'
 def awscmdtext = awscmd.execute().text
 def returnResult = [:]

 def slurper = new JsonSlurper()
 def result = slurper.parseText(awscmdtext)
 result.Reservations.Instances.each { i ->
  def found = i.Tags[0].grep {
   (it.Key == 'Name') && (it.Value == keyvalue)
  }  
  if (found.size() > 0) {
   returnResult.privateIpAddress = i[0].PrivateIpAddress
   returnResult.publicIpAddress =  i[0].PublicIpAddress
  }
 }
 returnResult
}

def authorizeSecurityGroupIngress(comment, groupID, cidr, port) {
 def proc
 def sb

 def cmd = 
       "aws ec2 authorize-security-group-ingress " +
       " --group-id $groupID" +
       " --cidr $cidr/32" +
       " --port $port " +
       " --protocol tcp " +
       " --region us-east-1 " 
 proc = cmd.execute()
 sb = new StringBuffer()
 proc.consumeProcessErrorStream(sb)
 println "comment: \n$comment"
 println "generated AWS CLI command: \n$cmd"
 println "stdout: ${proc.text}"
 println "stderr: ${sb.toString()}"
 println ""
}

def updateLogstashForwarderConfFileLocalhost(confFile, ip) {
 def f = new File(confFile)
 f.write(f.text.replaceAll('localhost', ip))
}

/**
* Update AWS security groups
**/

def logstashForwarderIPs             = getInstanceIPAddresses('craigLF')
def logstashForwarderSecurityGroupID = getSecurityGroupID('craiglf-SecurityGroup')

def logstashIPs                      = getInstanceIPAddresses('craigLg')
def logstashSecurityGroupID          = getSecurityGroupID('craiglg-SecurityGroup')

authorizeSecurityGroupIngress(
 'allow LF to receive from Lg on 5043', 
 logstashForwarderSecurityGroupID, 
 logstashIPs.privateIpAddress, 
 '5043')

authorizeSecurityGroupIngress(
 'allow Lg to receive from LF on 5043', 
 logstashSecurityGroupID, 
 logstashForwarderIPs.privateIpAddress, 
 '5043')

/**
* Update /etc/logstash-forwarder.conf
**/

def confFile = args[0]
assert confFile == '/etc/logstash-forwarder.conf'
updateLogstashForwarderConfFileLocalhost(confFile, logstashIPs.privateIpAddress)
